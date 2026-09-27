# Handoff Report: GraphRAG Architecture & Topological Attacks (Survey 2)

**Agent**: `explorer_survey_2`  
**Working Directory**: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_survey_2`  
**Parent Orchestrator**: `dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635`  
**Type**: Hard Handoff (Investigation & Architecture Survey Complete)  

---

## 1. Observation

1. **Catastrophic Clean Recall@5 in Existing Benchmark Report**:
   - File: `outputs/reports/rag_poisoning_comparison_report.md:33, 127-131`
   - Quoting lines 127-131:
     ```markdown
     | RAG Engine      | Overall Clean Recall@5   | CVE RCM Queries (Text-heavy)   | ATT&CK Attribution (Graph-heavy)   |
     |-----------------|--------------------------|--------------------------------|------------------------------------|
     | Sparse-BM25     | 22.2%                    | 40.0% (20/50)                  | 8.0% (4/50)                        |
     | Dense-FAISS     | 3.7%                     | 0.0% (0/50)                    | 12.0% (6/50)                       |
     | Hybrid-Reranker | 22.3%                    | 40.0% (20/50)                  | 8.0% (4/50)                        |
     | GraphRAG        | 1.0%                     | 0.0% (0/50)                    | 4.0% (2/50)                        |
     ```
   - GraphRAG achieved **1.0% Clean Recall@5** overall (0/50 on CVE queries, 2/50 on ATT&CK attribution queries).

2. **Entity Blacklisting Mechanism**:
   - File: `src/engines/retrievers.py:341-344`
   - Quoting lines 341-344:
     ```python
     for node, data in self.graph.nodes(data=True):
         # Exclude document nodes
         if node in self.doc_map or data.get("node_type") == "document":
             continue
     ```
   - All nodes whose identifier matches any document ID in `self.doc_map` are explicitly skipped during entity extraction from user queries.
   - Command run:
     `.\.venv\Scripts\python.exe -c "from src.corpus.real_cti_loader import RealCTILoader; from src.corpus.real_query_loader import RealQueryLoader; from src.engines.retrievers import GraphRAGRetriever; ..."`
   - Result: Across the 100 real CTI gold queries, **81 out of 100 (81.0%) produced empty entity matches (`matched = []`)**, while the other 19 matched only generic strings (`['malware']`, `['tool']`). Zero queries matched the focal CVE, technique ID, or threat actor.

3. **Single-Namespace Node Collision**:
   - File: `src/engines/retrievers.py:307-321`
   - Quoting lines 307-313:
     ```python
     for doc in self.documents:
         self.graph.add_node(doc.id, node_type="document", title=doc.title, is_poisoned=doc.is_poisoned)
         for entity in doc.entities:
             if not self.graph.has_node(entity):
                 self.graph.add_node(entity, node_type="entity")
             self.graph.add_edge(doc.id, entity, relation="MENTIONS")
             self.graph.add_edge(entity, doc.id, relation="MENTIONED_IN")
     ```
   - When `doc.id == entity` (e.g. `doc.id = "CVE-2021-44228"` and `entity = "CVE-2021-44228"`), line 310 evaluates to false; the node retains `node_type="document"`. Lines 312-313 add reflexive self-loops on the document node.
   - Degree normalization in lines 371-385 computes `self.graph.degree(node)`, mixing document-mention degrees with ontology relation degrees, severely inflating degrees and over-penalizing authentic documents.

4. **Silent Lexical Fallback Degradation**:
   - File: `src/engines/retrievers.py:387-393`
   - Quoting lines 387-393:
     ```python
     if not doc_scores:
         # Fallback to lexical token match
         for doc in self.documents:
             match_count = sum(1 for w in query.lower().split() if w in doc.text.lower())
             if match_count > 0:
                 doc_scores[doc.id] = float(match_count)
     ```
   - No logger call, no metric recording, no `metadata` flag.
   - In `outputs/reports/rag_poisoning_comparison_report.md:37, 49`, GraphRAG scored exactly **80.0% ASR** on all attacks with `query_echo=True` (`SPARSE_B1`, `DENSE_B1`, `HYBRID_B1`, `GRAPH_B1`) because the echoed queries saturated the fallback token counter. For `PURE_TOPOLOGICAL_B1` (neutral text, no query echo), ASR was 0.0% because the fallback score was 0.

5. **Topological Attack Formulation**:
   - File: `src/attacks/poisoning.py:188-243` (`PureTopologicalPoisonAttacker`)
   - Attacker injects 40 dummy bridge nodes $B_i$: `term -> USES/MITIGATES -> B_i -> ATTRIBUTED_TO -> poison_id`.
   - In the benchmark, `term` was blocked by line 343; the 40 bridges were never reached; traversal did not occur.

6. **Empirical Remediation Results**:
   - Implemented dual-namespace prototype (`doc:{id}` and `ent:{name}`) and tested against full real CTI corpus:
     - Overall Clean Recall@5: **86.0%** (86/100) vs Baseline **1.0%**
     - CVE Recall@5: **100.0%** (50/50) vs Baseline **0.0%**
     - STIX Attribution Recall@5: **72.0%** (36/50) vs Baseline **4.0%**
     - Pure topological traversal: **80 paths traversed**, poison score `0.3917` vs clean score `0.1754`.

---

## 2. Logic Chain

1. **Step 1 (From Observation 1 & 2)**: The 1.0% Clean Recall@5 was directly caused by line 343 (`if node in self.doc_map: continue`). In CTI benchmarks, document IDs are standard CTI identifiers (`CVE-2021-44228`, `T1059.001`, `APT28`). Blacklisting all `doc.id`s from entity extraction effectively blinded GraphRAG from recognizing the core subject of the query.
2. **Step 2 (From Observation 3)**: The absence of namespace prefixes caused document nodes and entity nodes to overwrite each other. When `doc.id == entity`, the node was tagged as `"document"` and therefore excluded from entity matching. Concurrently, NetworkX `degree()` conflated document-entity incidence with STIX relation edges, inflating node degrees and causing severe degree penalty in the retrieval scoring formula.
3. **Step 3 (From Observation 4)**: Because entity extraction returned `[]` for 81% of queries, GraphRAG fell back to `query.lower().split()` token matching in nearly all evaluations. This fallback was completely unlogged and untracked.
4. **Step 4 (From Observation 4 & 5)**: Because `PureTopologicalPoisonAttacker` uses neutral bulletin text without echoing query keywords, its fallback score was 0. The benchmark's claim that GraphRAG possessed 100% topological resistance was an illusion produced by an entity-extraction crash falling back to lexical search.
5. **Step 5 (From Observation 6)**: Introducing explicit namespace separation (`doc:` and `ent:`), matching entities against `node_type == "entity"`, and calculating degree normalization separately over entity and document sets immediately restored Clean Recall@5 to **86.0%** and activated topological attack paths (80 paths traversed).

---

## 3. Caveats

1. **Entity Extraction Speed in Python**: Matching all entity names against query strings sequentially using Python regex over ~20,000 entities takes ~150-200ms per query in pure Python. For enterprise scale (24,000 CVEs), pre-filtering with fast regexes (e.g. `CVE-\d{4}-\d{4,}` and ATT&CK ID patterns `[TSGM]\d{4}`) or an Aho-Corasick / FlashText automaton is recommended to keep query latency low (<20ms).
2. **2-Hop Decay Weighting**: The weighting parameters ($w_1 = 2.0$, $w_2 = 1.0$) perform well for 1-hop and 2-hop searches, but higher hop counts (>2) should be avoided to prevent graph sprawl and memory blow-up.
3. **Defense Calibration**: While `PureTopologicalPoisonAttacker` now successfully interacts with the query graph and can hijack Top-1 without query echo, `GraphConsensusValidator` in `src/defense/sanitizers.py` only validates disallowed target strings and should be upgraded to detect topological bridge anomalies (e.g., disproportionate in/out degree ratios on synthetic bridge nodes).

---

## 4. Conclusion

Requirement R2 addresses three critical benchmark flaws:
- **Class A4**: Artificial suppression of CTI entities matching document names.
- **Class B4**: Single-namespace graph collisions and distorted degree normalization.
- **Class B3**: Silent, unlogged lexical fallback degradation.

Remediation is straightforward, mathematically sound, and empirically verified:
1. Separate namespaces in `nx.MultiDiGraph` using `doc:{doc.id}` and `ent:{entity_name}`.
2. In `_extract_query_entities()`, match solely on nodes where `node_type == "entity"` without `doc_map` filtering.
3. In `retrieve()`, traverse `ent -> doc` for 1-hop and `ent -> ent -> doc` for 2-hop, normalizing degrees cleanly.
4. Log all fallbacks, record `fallback_used` in `RetrievalResult.metadata`, and expose `graph_fallback_rate` in `EngineBenchmarkResult`.
5. Expected outcome: **Clean Recall@5 increases from 1.0% to 86.0%** (surpassing the 70% acceptance threshold), and topological attacks exhibit measurable, verifiable graph interaction.

---

## 5. Verification Method

To independently verify all findings and validate the remediation:

1. **Run Current Test Suite**:
   ```pwsh
   .\.venv\Scripts\pytest.exe tests/ -v
   ```
   Confirm that all 71 existing unit tests currently pass.

2. **Verify Entity Extraction Blindness in Current Code**:
   ```pwsh
   .\.venv\Scripts\python.exe -c "from src.corpus.dataset import build_cti_knowledge_base, build_gold_benchmark_queries; from src.engines.retrievers import GraphRAGRetriever; r = GraphRAGRetriever(); r.build_index(build_cti_knowledge_base()); print([(q.id, r._extract_query_entities(q.query_text)) for q in build_gold_benchmark_queries()])"
   ```
   Observe that `CVE-2021-44228`, `CVE-2023-34362`, `APT28`, `T1059.001`, and `CVE-2024-21887` are missing from the extracted entities.

3. **Verify Remediation Performance (Clean Recall@5 >= 70%)**:
   Inspect the simulation script and output documented in Section 6 and Section 1 of `analysis.md`. Running the remediated dual-namespace logic on the authentic dataset yields:
   ```
   Overall Clean Recall@5: 86/100 = 86.0%
   CVE Recall@5: 50/50 = 100.0%
   STIX Attribution Recall@5: 36/50 = 72.0%
   ```

4. **Invalidation Conditions**:
   - If Clean Recall@5 on the real CTI dataset remains below 70.0%.
   - If `PureTopologicalPoisonAttacker` fails to traverse paths to the target poison document.
   - If fallback occurs without a warning log or without `metadata["fallback_used"] = True`.
