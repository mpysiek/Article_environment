"""Adversarial stress tests for Milestone 1 (Targeting-Aware Evaluation and Separation).

Comprehensive test suite verifying:
1. RetrievalResult schema boundary conditions, type robustness, and legacy backward compatibility.
2. Evaluator targeting logic against substring collisions, regex characters, unicode, and corruptions.
3. Top-k rank permutations (rank 1 untargeted / rank 2 targeted, beyond rank 5, multiple poisons).
4. High-density background contamination (60+ foreign poisons) across all 4 retrievers
   (BM25, DenseFAISS, HybridRerank, GraphRAG including graph traversal and fallback).
"""

from pathlib import Path
import pytest
import numpy as np

from src.corpus.dataset import CTIDocument, RetrievalResult, GoldQuery
from src.engines.retrievers import (
    BM25Retriever,
    DenseFAISSRetriever,
    HybridRerankRetriever,
    GraphRAGRetriever,
)
from src.evaluation.metrics import Evaluator, EngineBenchmarkResult, GenerationTrace


# ===========================================================================
# 1. RetrievalResult Schema & Type Robustness
# ===========================================================================

class TestAdversarialRetrievalResultSchema:
    def test_unpoisoned_with_target_query_not_flagged(self):
        """If is_poisoned=False, poison_target_query must NEVER trigger targeted ASR."""
        r = RetrievalResult(
            doc_id="CLEAN-BUG-01",
            score=0.99,
            rank=1,
            title="Clean Title",
            text="Clean Text",
            is_poisoned=False,
            doc_type="cve",
            poison_target_query="Q-TARGET-1",
            poison_type="dense",
        )
        q = GoldQuery(
            id="Q-TARGET-1",
            query_text="What is the vulnerability?",
            category="cve",
            ground_truth_doc_ids=["CLEAN-BUG-01"],
            ground_truth_answer="Answer",
            target_poison_assertion="Assertion",
        )
        res = Evaluator.evaluate_engine("Dense-FAISS", "dense", [q], {"Q-TARGET-1": [r]})
        assert res.retrieval_asr_targeted == 0.0, "is_poisoned=False must never count as targeted ASR"
        assert res.retrieval_asr_any == 0.0, "is_poisoned=False must never count as any poison"
        assert res.retrieval_asr_untargeted == 0.0
        assert res.clean_recall_top5 == 1.0

    def test_poisoned_with_none_or_empty_target(self):
        """Poisoned document with poison_target_query=None or '' must be untargeted only."""
        for target_val in [None, ""]:
            r = RetrievalResult(
                doc_id="POISON-NO-TARGET",
                score=0.99,
                rank=1,
                title="Poison Title",
                text="Adversarial Text",
                is_poisoned=True,
                doc_type="poison",
                poison_target_query=target_val,
                poison_type="sparse",
            )
            q = GoldQuery(
                id="Q-TARGET-1",
                query_text="What is the vulnerability?",
                category="cve",
                ground_truth_doc_ids=["GT-01"],
                ground_truth_answer="Answer",
                target_poison_assertion="Assertion",
            )
            res = Evaluator.evaluate_engine("BM25", "sparse", [q], {"Q-TARGET-1": [r]})
            assert res.retrieval_asr_targeted == 0.0, f"Target val {target_val!r} must not count as targeted"
            assert res.retrieval_asr_any == 1.0
            assert res.retrieval_asr_untargeted == 1.0

    def test_non_string_poison_target_query_types(self):
        """Corrupted poison_target_query (int, float, list, bool) must not crash Evaluator."""
        corrupted_targets = [12345, 3.1415, True, False, ["Q-TARGET-1"], {"nested": "value"}]
        q = GoldQuery(
            id="Q-TARGET-1",
            query_text="What is the vulnerability?",
            category="cve",
            ground_truth_doc_ids=["GT-01"],
            ground_truth_answer="Answer",
            target_poison_assertion="Assertion",
        )
        for val in corrupted_targets:
            # If val is a dict and passed to RetrievalResult via metadata kwargs, handled safely
            r = RetrievalResult(
                doc_id="POISON-CORRUPT",
                score=0.99,
                rank=1,
                title="Poison",
                text="Text",
                is_poisoned=True,
                doc_type="poison",
                poison_target_query=val if not isinstance(val, dict) else None,
                poison_type="sparse",
            )
            res = Evaluator.evaluate_engine("BM25", "sparse", [q], {"Q-TARGET-1": [r]})
            assert res.retrieval_asr_targeted == 0.0
            assert res.retrieval_asr_any == 1.0
            assert res.retrieval_asr_untargeted == 1.0

    def test_legacy_positional_arguments_matrix(self):
        """Ensure full compatibility matrix with 7, 8, 9, and 10 positional arguments."""
        # 7 args: doc_id, score, rank, title, text, is_poisoned, doc_type
        r7 = RetrievalResult("D1", 1.0, 1, "T", "Txt", False, "cve")
        assert r7.poison_target_query is None
        assert r7.metadata == {}

        # 8 args with dict: legacy positional metadata
        r8_dict = RetrievalResult("D2", 1.0, 1, "T", "Txt", False, "cve", {"k": "v"})
        assert r8_dict.poison_target_query is None
        assert r8_dict.metadata == {"k": "v"}

        # 8 args with string: poison_target_query
        r8_str = RetrievalResult("D3", 1.0, 1, "T", "Txt", True, "poison", "Q-1")
        assert r8_str.poison_target_query == "Q-1"
        assert r8_str.poison_type is None
        assert r8_str.metadata == {}

        # 9 args: doc_id..poison_type
        r9 = RetrievalResult("D4", 1.0, 1, "T", "Txt", True, "poison", "Q-1", "dense")
        assert r9.poison_target_query == "Q-1"
        assert r9.poison_type == "dense"
        assert r9.metadata == {}

        # 10 args: doc_id..metadata
        r10 = RetrievalResult("D5", 1.0, 1, "T", "Txt", True, "poison", "Q-1", "dense", {"engine": "faiss"})
        assert r10.poison_target_query == "Q-1"
        assert r10.poison_type == "dense"
        assert r10.metadata == {"engine": "faiss"}


# ===========================================================================
# 2. Substring Collisions, Regex Metacharacters & Special Encodings
# ===========================================================================

class TestEvaluatorAdversarialMatching:
    def test_substring_collisions_never_match(self):
        """Query ID Q1 must NOT match Q10, Q11, Q1_extra, or prefix_Q1."""
        q = GoldQuery(
            id="Q1",
            query_text="Explain Log4Shell RCE",
            category="cve",
            ground_truth_doc_ids=["GT-1"],
            ground_truth_answer="Answer",
            target_poison_assertion="Assertion",
        )
        near_miss_targets = [
            "Q10", "Q11", "Q100", "Q1_extra", "prefix_Q1", "Q-1", "Q 1",
            "Explain Log4Shell RCE in detail",  # Substring of query text
            "Please Explain Log4Shell RCE",
            "q1",  # Case difference
        ]
        for foreign_target in near_miss_targets:
            r = RetrievalResult(
                doc_id=f"P_{foreign_target}",
                score=0.95,
                rank=1,
                title="Foreign Poison",
                text="Adversarial Text",
                is_poisoned=True,
                doc_type="poison",
                poison_target_query=foreign_target,
            )
            res = Evaluator.evaluate_engine("BM25", "sparse", [q], {"Q1": [r]})
            assert res.retrieval_asr_targeted == 0.0, f"Foreign target {foreign_target!r} must NOT match Q1!"
            assert res.retrieval_asr_any == 1.0
            assert res.retrieval_asr_untargeted == 1.0

    def test_special_regex_and_sql_characters(self):
        """Query IDs or texts containing regex characters, quotes, or SQL fragments."""
        special_ids = [
            r"Q[.*+?^${}()|\[\]\\]",
            "Q-CVE' OR '1'='1; --",
            '<script>alert("xss")</script>',
            "Q-ümlaut-ü-ö-ä-ß-日本語-Кириллица",
            "Q-with\nnewline\tand\ttabs\r\n",
        ]
        for sid in special_ids:
            q = GoldQuery(
                id=sid,
                query_text=f"Query text for {sid}",
                category="cve",
                ground_truth_doc_ids=["GT-01"],
                ground_truth_answer="Answer",
                target_poison_assertion="Assertion",
            )
            # Matching poison
            r_match = RetrievalResult(
                doc_id="P_MATCH",
                score=0.99,
                rank=1,
                title="P",
                text="Text",
                is_poisoned=True,
                doc_type="poison",
                poison_target_query=sid,
            )
            res_match = Evaluator.evaluate_engine("Dense-FAISS", "dense", [q], {sid: [r_match]})
            assert res_match.retrieval_asr_targeted == 1.0, f"Special id {sid!r} should match exactly"

            # Non-matching poison (altered by 1 character)
            r_mismatch = RetrievalResult(
                doc_id="P_MISMATCH",
                score=0.99,
                rank=1,
                title="P",
                text="Text",
                is_poisoned=True,
                doc_type="poison",
                poison_target_query=sid + "_diff",
            )
            res_mismatch = Evaluator.evaluate_engine("Dense-FAISS", "dense", [q], {sid: [r_mismatch]})
            assert res_mismatch.retrieval_asr_targeted == 0.0, f"Altered special id {sid!r} must not match"
            assert res_mismatch.retrieval_asr_any == 1.0


# ===========================================================================
# 3. Top-k Permutations and Rank Stress
# ===========================================================================

class TestTopKRankPermutations:
    @pytest.fixture
    def sample_query(self):
        return GoldQuery(
            id="Q-TARGET",
            query_text="What is the severity of CVE-2021-44228?",
            category="cve",
            ground_truth_doc_ids=["GT-CLEAN"],
            ground_truth_answer="Critical 10.0 CVSS",
            target_poison_assertion="It is benign",
        )

    def test_rank1_untargeted_rank2_targeted(self, sample_query):
        """Top-1 is foreign poison, Top-2 is targeted poison.

        Metrics must reflect:
        - retrieval_asr_targeted_top1 == 0.0
        - retrieval_asr_any_top1 == 1.0
        - retrieval_asr_untargeted_top1 == 1.0
        - retrieval_asr_targeted_top5 == 1.0
        - retrieval_asr_any_top5 == 1.0
        - retrieval_asr_untargeted_top5 == 0.0
        """
        results = [
            RetrievalResult("P-FOREIGN", 0.99, 1, "Foreign P", "Txt", True, "poison", poison_target_query="Q-OTHER"),
            RetrievalResult("P-TARGETED", 0.95, 2, "Targeted P", "Txt", True, "poison", poison_target_query="Q-TARGET"),
            RetrievalResult("CLEAN-1", 0.90, 3, "Clean 1", "Txt", False, "cve"),
            RetrievalResult("CLEAN-2", 0.85, 4, "Clean 2", "Txt", False, "cve"),
            RetrievalResult("CLEAN-3", 0.80, 5, "Clean 3", "Txt", False, "cve"),
        ]
        res = Evaluator.evaluate_engine("Dense-FAISS", "dense", [sample_query], {"Q-TARGET": results})
        assert res.retrieval_asr_targeted_top1 == 0.0
        assert res.retrieval_asr_any_top1 == 1.0
        assert res.retrieval_asr_untargeted_top1 == 1.0
        assert res.retrieval_asr_targeted_top5 == 1.0
        assert res.retrieval_asr_any_top5 == 1.0
        assert res.retrieval_asr_untargeted_top5 == 0.0
        assert res.retrieval_asr == 1.0  # Primary alias points to targeted_top5

        t = res.traces[0]
        assert t.has_poison_in_top1 is True
        assert t.has_targeted_poison_in_top1 is False
        assert t.has_untargeted_poison_in_top1 is True
        assert t.has_poison_in_top5 is True
        assert t.has_targeted_poison_in_top5 is True
        assert t.has_untargeted_poison_in_top5 is False

    def test_targeted_at_rank_6_cutoff_exclusion(self, sample_query):
        """Targeted poison at rank 6 (outside Top-5) must not count toward targeted ASR@5."""
        results = [
            RetrievalResult(f"CLEAN-{i}", 1.0 - i * 0.05, i, f"Clean {i}", "Txt", False, "cve")
            for i in range(1, 6)
        ]
        results.append(
            RetrievalResult("P-TARGETED", 0.70, 6, "Targeted P", "Txt", True, "poison", poison_target_query="Q-TARGET")
        )
        res = Evaluator.evaluate_engine("BM25", "sparse", [sample_query], {"Q-TARGET": results})
        assert res.retrieval_asr_targeted == 0.0
        assert res.retrieval_asr_any == 0.0
        assert res.retrieval_asr_untargeted == 0.0

    def test_foreign_at_rank_4_targeted_at_rank_7(self, sample_query):
        """Foreign poison at rank 4, targeted poison at rank 7.

        Should register untargeted contamination at top-5, but ZERO targeted ASR.
        """
        results = [
            RetrievalResult("CLEAN-1", 0.95, 1, "Clean 1", "Txt", False, "cve"),
            RetrievalResult("CLEAN-2", 0.90, 2, "Clean 2", "Txt", False, "cve"),
            RetrievalResult("CLEAN-3", 0.85, 3, "Clean 3", "Txt", False, "cve"),
            RetrievalResult("P-FOREIGN", 0.80, 4, "Foreign P", "Txt", True, "poison", poison_target_query="Q-OTHER"),
            RetrievalResult("CLEAN-5", 0.75, 5, "Clean 5", "Txt", False, "cve"),
            RetrievalResult("CLEAN-6", 0.70, 6, "Clean 6", "Txt", False, "cve"),
            RetrievalResult("P-TARGETED", 0.65, 7, "Targeted P", "Txt", True, "poison", poison_target_query="Q-TARGET"),
        ]
        res = Evaluator.evaluate_engine("BM25", "sparse", [sample_query], {"Q-TARGET": results})
        assert res.retrieval_asr_targeted == 0.0
        assert res.retrieval_asr_any == 1.0
        assert res.retrieval_asr_untargeted == 1.0

    def test_multiple_targeted_poisons_top5_query_level_normalization(self, sample_query):
        """Top-5 with 3 targeted poisons must count as 1.0 ASR for the query, not 3.0."""
        results = [
            RetrievalResult(f"P-TARGETED-{i}", 0.99 - i * 0.05, i, f"Targeted P {i}", "Txt", True, "poison", poison_target_query="Q-TARGET")
            for i in range(1, 4)
        ] + [
            RetrievalResult("CLEAN-4", 0.80, 4, "Clean 4", "Txt", False, "cve"),
            RetrievalResult("CLEAN-5", 0.75, 5, "Clean 5", "Txt", False, "cve"),
        ]
        res = Evaluator.evaluate_engine("Dense-FAISS", "dense", [sample_query], {"Q-TARGET": results})
        assert res.retrieval_asr_targeted == 1.0
        assert res.retrieval_asr_any == 1.0
        assert res.retrieval_asr_untargeted == 0.0


# ===========================================================================
# 4. High-Density Background Contamination Across All 4 Retrievers
# ===========================================================================

class TestHighDensityBackgroundContamination:
    @pytest.fixture(scope="class")
    def contaminated_corpus_setup(self):
        """Builds a corpus with 10 clean CTI documents + 60 foreign poison documents targeting Q-FOREIGN-999.

        Foreign poisons heavily spam CTI terms to lure BM25, Dense, Hybrid, and Graph retrievers.
        """
        clean_docs = [
            CTIDocument(
                id=f"CLEAN-CVE-{i}",
                title=f"Vulnerability Bulletin CVE-2023-100{i}",
                text=f"Official patch and mitigation for vulnerability CVE-2023-100{i} in software component-{i}. CVSS 8.5.",
                doc_type="cve",
                entities=[f"CVE-2023-100{i}", f"component-{i}"],
                relations=[{"source": f"CVE-2023-100{i}", "target": f"component-{i}", "relation": "AFFECTS"}],
                is_poisoned=False,
            )
            for i in range(10)
        ]

        # 60 foreign poison documents targeting Q-FOREIGN-999
        foreign_poisons = [
            CTIDocument(
                id=f"FOREIGN-POISON-{i}",
                title=f"Security advisory update regarding CVE-2023-100{i % 10} and component-{i % 10}",
                text=f"Critical mitigation update for CVE-2023-100{i % 10} in component-{i % 10}: false alarm, no exploitation is possible. Adversarial payload {i}.",
                doc_type="poison",
                entities=[f"CVE-2023-100{i % 10}", f"component-{i % 10}"],
                relations=[{"source": f"CVE-2023-100{i % 10}", "target": f"component-{i % 10}", "relation": "MITIGATES"}],
                is_poisoned=True,
                poison_target_query="Q-FOREIGN-999",
                poison_type="dense",
            )
            for i in range(60)
        ]

        full_corpus = clean_docs + foreign_poisons

        # Benchmark queries testing legitimate CVEs (NO targeted poisons exist for these queries!)
        test_queries = [
            GoldQuery(
                id=f"Q-TEST-{i}",
                query_text=f"What is the mitigation for CVE-2023-100{i} in component-{i}?",
                category="cve",
                ground_truth_doc_ids=[f"CLEAN-CVE-{i}"],
                ground_truth_answer=f"Official patch for component-{i}",
                target_poison_assertion="No exploitation possible",
            )
            for i in range(5)
        ]

        return full_corpus, test_queries

    def test_bm25_high_density_contamination_rejection(self, contaminated_corpus_setup):
        corpus, test_queries = contaminated_corpus_setup
        retriever = BM25Retriever()
        retriever.build_index(corpus)

        retrieval_outputs = {}
        for q in test_queries:
            results = retriever.retrieve(q.query_text, top_k=5)
            retrieval_outputs[q.id] = results

        res = Evaluator.evaluate_engine("BM25", "sparse", test_queries, retrieval_outputs)
        # Because all 60 poisons target Q-FOREIGN-999, targeted ASR MUST BE ZERO!
        assert res.retrieval_asr_targeted == 0.0, "BM25 must have 0.0 targeted ASR despite heavy foreign contamination"
        assert res.retrieval_asr == 0.0
        # Background contamination should be detected
        assert res.retrieval_asr_any > 0.0, "Foreign poisons should be detected in background contamination"
        assert res.retrieval_asr_untargeted == res.retrieval_asr_any

    def test_dense_faiss_high_density_contamination_rejection(self, contaminated_corpus_setup):
        corpus, test_queries = contaminated_corpus_setup
        retriever = DenseFAISSRetriever()
        retriever.build_index(corpus)

        retrieval_outputs = {}
        for q in test_queries:
            results = retriever.retrieve(q.query_text, top_k=5)
            retrieval_outputs[q.id] = results

        res = Evaluator.evaluate_engine("Dense-FAISS", "dense", test_queries, retrieval_outputs)
        assert res.retrieval_asr_targeted == 0.0, "Dense-FAISS must have 0.0 targeted ASR under foreign contamination"
        assert res.retrieval_asr == 0.0
        assert res.retrieval_asr_any > 0.0
        assert res.retrieval_asr_untargeted == res.retrieval_asr_any

    def test_hybrid_reranker_high_density_contamination_rejection(self, contaminated_corpus_setup):
        corpus, test_queries = contaminated_corpus_setup
        bm25 = BM25Retriever()
        dense = DenseFAISSRetriever()
        bm25.build_index(corpus)
        dense.build_index(corpus)
        hybrid = HybridRerankRetriever(bm25, dense)
        hybrid.build_index(corpus)

        retrieval_outputs = {}
        for q in test_queries:
            results = hybrid.retrieve(q.query_text, top_k=5)
            retrieval_outputs[q.id] = results

        res = Evaluator.evaluate_engine("Hybrid-Reranker", "hybrid", test_queries, retrieval_outputs)
        assert res.retrieval_asr_targeted == 0.0, "Hybrid-Reranker must have 0.0 targeted ASR under foreign contamination"
        assert res.retrieval_asr == 0.0
        assert res.retrieval_asr_any > 0.0
        assert res.retrieval_asr_untargeted == res.retrieval_asr_any

    def test_graphrag_high_density_contamination_rejection(self, contaminated_corpus_setup):
        corpus, test_queries = contaminated_corpus_setup
        retriever = GraphRAGRetriever()
        retriever.build_index(corpus)

        retrieval_outputs = {}
        for q in test_queries:
            results = retriever.retrieve(q.query_text, top_k=5)
            retrieval_outputs[q.id] = results

        res = Evaluator.evaluate_engine("GraphRAG", "graph", test_queries, retrieval_outputs)
        assert res.retrieval_asr_targeted == 0.0, "GraphRAG must have 0.0 targeted ASR under foreign contamination"
        assert res.retrieval_asr == 0.0
        assert res.retrieval_asr_any > 0.0
        assert res.retrieval_asr_untargeted == res.retrieval_asr_any

    def test_graphrag_fallback_preserves_targeting(self):
        """When GraphRAG matches NO entities and uses lexical fallback, targeting must be preserved."""
        poison_doc = CTIDocument(
            id="POISON-FALLBACK-1",
            title="Non-entity document",
            text="UnusualTermX99 mitigation advisory",
            doc_type="poison",
            entities=[],  # No entities in graph!
            relations=[],
            is_poisoned=True,
            poison_target_query="Q-FALLBACK",
            poison_type="sparse",
        )
        retriever = GraphRAGRetriever()
        retriever.build_index([poison_doc])

        # Query with UnusualTermX99 triggers fallback lexical matching
        results = retriever.retrieve("What is UnusualTermX99?", top_k=1)
        assert len(results) == 1
        r = results[0]
        assert r.is_poisoned is True
        assert r.poison_target_query == "Q-FALLBACK"
        assert r.poison_type == "sparse"

        q = GoldQuery("Q-FALLBACK", "What is UnusualTermX99?", "cve", ["GT"], "Ans", "Assert")
        res = Evaluator.evaluate_engine("GraphRAG", "graph", [q], {"Q-FALLBACK": results})
        assert res.retrieval_asr_targeted == 1.0
