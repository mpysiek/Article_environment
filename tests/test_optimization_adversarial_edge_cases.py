import pytest
import networkx as nx
from src.corpus.dataset import CTIDocument
from src.engines.retrievers import BM25Retriever, GraphRAGRetriever

def make_doc(doc_id: str, title: str, text: str, is_poisoned: bool = False, entities=None, relations=None):
    return CTIDocument(
        id=doc_id,
        title=title,
        text=text,
        doc_type="cve",
        is_poisoned=is_poisoned,
        entities=entities or [],
        relations=relations or []
    )

class TestOptimizationEdgeCases:
    def test_bm25_poison_docs_prepended_desynchronization(self):
        """Verify that prepending poison docs does NOT desynchronize BM25 doc_ids and scores."""
        clean1 = make_doc("CVE-CLEAN-1", "Apache Tomcat", "Remote code execution vulnerability in Apache Tomcat web server.")
        clean2 = make_doc("CVE-CLEAN-2", "Nginx Proxy", "Buffer overflow in Nginx HTTP reverse proxy module.")
        clean3 = make_doc("CVE-CLEAN-3", "OpenSSL Crypto", "Timing attack vulnerability in OpenSSL RSA key exchange.")
        poison = make_doc("CVE-POISON-1", "Poison Payload", "Malicious inject Apache Tomcat override payload.", is_poisoned=True)

        bm25_opt = BM25Retriever()
        bm25_opt.build_index([clean1, clean2, clean3])

        # Baseline BM25 (fresh build without incremental logic)
        bm25_base = BM25Retriever()

        # Test case: poison doc is FIRST, before clean docs
        mixed_docs = [poison, clean1, clean2, clean3]
        bm25_base.build_index(mixed_docs)
        bm25_opt.build_index(mixed_docs)

        res_base = bm25_base.retrieve("Apache Tomcat", top_k=4)
        res_opt = bm25_opt.retrieve("Apache Tomcat", top_k=4)

        assert len(res_base) == len(res_opt)
        for rb, ro in zip(res_base, res_opt):
            assert rb.doc_id == ro.doc_id
            assert abs(rb.score - ro.score) < 1e-6
            assert rb.is_poisoned == ro.is_poisoned

    def test_bm25_reordered_clean_docs_falls_back_safely(self):
        """Verify that passing clean docs in different order does not cause misaligned incremental reuse."""
        clean1 = make_doc("C1", "Doc 1", "Alpha beta gamma")
        clean2 = make_doc("C2", "Doc 2", "Delta epsilon zeta")
        poison = make_doc("P1", "Poison", "Alpha zeta poison", is_poisoned=True)

        bm25 = BM25Retriever()
        bm25.build_index([clean1, clean2])

        # Reorder clean docs: [clean2, clean1] + [poison]
        bm25.build_index([clean2, clean1, poison])

        res = bm25.retrieve("Alpha", top_k=3)
        doc_ids = [r.doc_id for r in res]
        # C1 and P1 have 'Alpha', C2 does not
        assert "C1" in doc_ids[:2]
        assert "P1" in doc_ids[:2]
        assert doc_ids[-1] == "C2"

    def test_bm25_empty_build_clears_base_cache(self):
        """Verify that build_index([]) clears base caching structures."""
        clean = make_doc("C1", "Doc 1", "Alpha beta")
        bm25 = BM25Retriever()
        bm25.build_index([clean])
        assert bm25._base_bm25 is not None

        bm25.build_index([])
        assert bm25.bm25 is None
        assert bm25._base_bm25 is None
        assert bm25._base_doc_ids is None
        assert bm25._base_corpus_tokens is None

    def test_graphrag_rebuild_base_entity_clears_delta_no_duplicates(self):
        """Verify that if graph is mutated directly, delta entities are not duplicated in extract_query_entities."""
        clean = make_doc("C1", "Tomcat Security", "Tomcat details", entities=["Apache Tomcat"])
        poison = make_doc("P1", "Poison Exploit", "Exploit details", is_poisoned=True, entities=["PoisonExploit"])

        graph = GraphRAGRetriever()
        graph.build_index([clean])
        assert len(graph._entity_candidates) == 1

        # Incremental build with poison
        graph.build_index([clean, poison])
        assert len(graph._delta_entity_candidates) == 1

        # Direct external modification to graph node count
        graph.graph.add_node("ent:AdHocEntity", node_type="entity")

        # Entity extraction should auto-rebuild base without duplicating delta entity
        matched = graph._extract_query_entities("PoisonExploit Apache Tomcat AdHocEntity")
        assert matched.count("PoisonExploit") == 1
        assert matched.count("Apache Tomcat") == 1
        assert matched.count("AdHocEntity") == 1

    def test_graphrag_rollback_preserves_clean_doc_on_collision(self):
        """Verify that if a poison doc shares an ID with clean doc, rollback restores clean doc_map."""
        clean = make_doc("CVE-COLLIDE", "Clean Title", "Clean text", entities=["CleanEnt"])
        poison = make_doc("CVE-COLLIDE", "Poison Title", "Poison text", is_poisoned=True, entities=["PoisonEnt"])

        graph = GraphRAGRetriever()
        graph.build_index([clean])
        assert graph.doc_map["CVE-COLLIDE"].title == "Clean Title"

        graph.build_index([clean, poison])
        assert graph.doc_map["CVE-COLLIDE"].title == "Poison Title"

        graph.rollback_poison()
        assert "CVE-COLLIDE" in graph.doc_map
        assert graph.doc_map["CVE-COLLIDE"].title == "Clean Title"

    def test_graphrag_ent_prefix_stripping_in_delta(self):
        """Verify that delta entities with ent: prefix in relations are stripped and searchable."""
        clean = make_doc("C1", "Clean", "Clean text", entities=["CleanEnt"])
        poison = make_doc(
            "P1", "Poison", "Poison text", is_poisoned=True,
            relations=[{"source": "ent:DeltaSpring", "relation": "EXPLOITS", "target": "CleanEnt"}]
        )

        graph = GraphRAGRetriever()
        graph.build_index([clean])
        graph.build_index([clean, poison])

        matched = graph._extract_query_entities("Details on DeltaSpring vulnerability")
        assert "DeltaSpring" in matched
        assert "ent:DeltaSpring" not in matched

    def test_graphrag_mixed_full_build_invalidates_stale_base(self):
        """Verify that a full build with poison docs invalidates base cache, preventing foreign poison leakage."""
        clean_a = make_doc("CA", "Corpus A", "Text A", entities=["EntityA"])
        clean_b = make_doc("CB", "Corpus B", "Text B", entities=["EntityB"])
        poison_b = make_doc("PB", "Poison B", "Poison B text", is_poisoned=True, entities=["PoisonB"])

        graph = GraphRAGRetriever()
        # Build A (base)
        graph.build_index([clean_a])
        assert graph._base_doc_ids == {"CA"}

        # Build mixed B (full build with poison)
        graph.build_index([clean_b, poison_b])
        assert graph._base_doc_ids is None  # Invalidated!

        # Build A again (should cleanly establish A as base)
        graph.build_index([clean_a])
        assert graph._base_doc_ids == {"CA"}
        assert not graph.graph.has_node("ent:PoisonB")
        assert not graph.graph.has_node("ent:EntityB")
        assert graph.graph.has_node("ent:EntityA")

    def test_graphrag_empty_build_resets_state(self):
        """Verify that build_index([]) cleanly resets all graph and base state."""
        clean = make_doc("C1", "Doc", "Text", entities=["Entity1"])
        graph = GraphRAGRetriever()
        graph.build_index([clean])
        assert graph._base_graph is not None

        graph.build_index([])
        assert graph.graph.number_of_nodes() == 0
        assert graph._base_graph is None
        assert graph._base_doc_ids is None
        assert graph.doc_map == {}
        assert len(graph._entity_candidates) == 0
