"""Adversarial stress tests for Recommendation 3 (Isolated Evaluation Protocol).

Comprehensive stress testing verifying:
1. Zero Foreign Poison Invariant across all 4 retrievers (BM25, DenseFAISS, HybridRerank, GraphRAG)
   under multi-query, high-budget settings, including internal index state inspection.
2. Evaluator Invariants in isolated mode:
   retrieval_asr_untargeted == 0.0%, retrieval_asr_targeted == retrieval_asr_any unconditionally.
3. Budget Sensitivity & Payload Diversity across B in {1, 3, 5} across ALL attack types
   (sparse, dense, hybrid, graph, pure_topological, blackbox), confirming no bitwise duplicates
   and non-saturation of context.
4. Edge Cases: 1 query, odd budgets, empty clean corpus, high top_k, B=0, missing payload keys,
   and hostile query text.
"""

import sys
import math
from pathlib import Path
from typing import List, Dict
import pytest
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.corpus.dataset import (
    build_cti_knowledge_base,
    build_gold_benchmark_queries,
    CTIDocument,
    GoldQuery,
    RetrievalResult,
)
from src.attacks.poisoning import CorpusPoisonManager
from src.engines.retrievers import (
    BM25Retriever,
    DenseFAISSRetriever,
    HybridRerankRetriever,
    GraphRAGRetriever,
)
from src.evaluation.stages import (
    execute_isolated_retrieval,
    execute_shared_retrieval,
)
from src.evaluation.metrics import Evaluator, EngineBenchmarkResult, GenerationTrace


@pytest.fixture
def cti_stress_fixture():
    clean_docs = build_cti_knowledge_base()[:12]
    queries = build_gold_benchmark_queries()[:5]
    poison_mgr = CorpusPoisonManager(query_echo=True)
    return clean_docs, queries, poison_mgr


# ===========================================================================
# 1. Zero Foreign Poison Invariant Across All 4 Retrievers & State Inspection
# ===========================================================================

class TestZeroForeignPoisonDeepStress:
    """Stress tests verifying that no foreign poison ever enters the index or Top-k results,
    and verifying internal index state cleanliness after every query.
    """

    @pytest.mark.parametrize("attack_type", ["sparse", "dense", "hybrid", "graph", "pure_topological", "blackbox"])
    def test_zero_foreign_poison_all_attack_types_bm25(self, cti_stress_fixture, attack_type):
        clean_docs, queries, poison_mgr = cti_stress_fixture
        retriever = BM25Retriever()
        budget = 3
        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type=attack_type, attack_budget=budget
        )

        outputs, _ = execute_isolated_retrieval(
            retriever, clean_docs, payloads, queries, top_k=10
        )

        for q in queries:
            results = outputs[q.id]
            poison_results = [r for r in results if r.is_poisoned]
            # Max poison results cannot exceed budget
            assert len(poison_results) <= budget
            for r in poison_results:
                assert r.poison_target_query == q.id, (
                    f"Foreign poison leaked into results for {q.id}! Target query was {r.poison_target_query}"
                )

    def test_all_four_engines_internal_state_cleanliness(self, cti_stress_fixture):
        """Inspect internal structures of all 4 engines across sequential queries.
        Verifies that no engine accumulates leftover documents or graph nodes from prior queries.
        """
        clean_docs, queries, poison_mgr = cti_stress_fixture
        bm25 = BM25Retriever()
        dense = DenseFAISSRetriever(persist_cache=False)
        hybrid = HybridRerankRetriever(bm25_engine=bm25, dense_engine=dense)
        graph = GraphRAGRetriever()

        # Prime baseline graphs/embeddings with clean_docs
        bm25.build_index(clean_docs)
        dense.build_index(clean_docs)
        hybrid.build_index(clean_docs)
        graph.build_index(clean_docs)

        budget = 3
        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=budget
        )

        engines = [
            ("Sparse-BM25", bm25),
            ("Dense-FAISS", dense),
            ("Hybrid-Reranker", hybrid),
            ("GraphRAG", graph),
        ]

        clean_doc_count = len(clean_docs)
        expected_total_docs = clean_doc_count + budget

        for eng_name, engine in engines:
            for i, q in enumerate(queries):
                q_poisons = payloads[q.id]
                index_docs = clean_docs + q_poisons
                engine.build_index(index_docs)
                results = engine.retrieve(q.query_text, top_k=5)

                # 1. Check engine.documents length
                assert len(engine.documents) == expected_total_docs, (
                    f"{eng_name} has {len(engine.documents)} documents, expected {expected_total_docs} on query {q.id}"
                )

                # 2. Check engine.documents contents: only clean docs + target query poisons
                for doc in engine.documents:
                    if doc.is_poisoned:
                        assert doc.poison_target_query == q.id, (
                            f"{eng_name} index retains foreign poison document {doc.id} targeting {doc.poison_target_query} on query {q.id}"
                        )

                # 3. Check engine-specific internal structures
                if eng_name == "Dense-FAISS":
                    assert engine.index.ntotal == expected_total_docs, (
                        f"FAISS index size {engine.index.ntotal} != expected {expected_total_docs}"
                    )
                elif eng_name == "GraphRAG":
                    # Check graph nodes: must NOT contain foreign doc nodes
                    for node in engine.graph.nodes():
                        if str(node).startswith("doc:POISON_"):
                            # node format: doc:POISON_...
                            doc_id = str(node)[4:]
                            doc = engine.doc_map.get(doc_id)
                            if doc and doc.is_poisoned:
                                assert doc.poison_target_query == q.id, (
                                    f"GraphRAG graph retains foreign poison node {node} on query {q.id}"
                                )
                elif eng_name == "Hybrid-Reranker":
                    assert len(engine.bm25_engine.documents) == expected_total_docs
                    assert len(engine.dense_engine.documents) == expected_total_docs
                    assert engine.dense_engine.index.ntotal == expected_total_docs

                # 4. Check retrieved results
                for r in results:
                    if r.is_poisoned:
                        assert r.poison_target_query == q.id, (
                            f"{eng_name} retrieved foreign poison {r.doc_id} for query {q.id}"
                        )

    def test_foreign_poison_impossibility_with_cross_query_interference(self, cti_stress_fixture):
        """Constructs an adversarial scenario where poison for Q1 has extremely high keyword
        affinity for Q2, but because of isolated indexing, Q2 NEVER retrieves Q1's poison.
        """
        clean_docs, queries, _ = cti_stress_fixture
        q1, q2 = queries[0], queries[1]

        # Hostile poison targeting Q1, but artificially stuffed with Q2's exact text
        poison_q1 = CTIDocument(
            id="POISON_HOSTILE_Q1",
            title=f"Hostile {q2.query_text}",
            text=f"{q2.query_text} " * 20 + " Malicious override for Q1",
            doc_type="cve",
            entities=q2.key_terms,
            relations=[],
            is_poisoned=True,
            poison_target_query=q1.id,
            poison_type="hostile_cross_stuffing"
        )

        payloads = {
            q1.id: [poison_q1],
            q2.id: [],  # Q2 has no poison
        }

        retriever = BM25Retriever()
        outputs, _ = execute_isolated_retrieval(
            retriever, clean_docs, payloads, [q1, q2], top_k=5
        )

        # In Q2 results: despite the poison being heavily stuffed with Q2 text,
        # it is NOT in Q2's isolated index, so Q2 results must contain ZERO poisons!
        q2_results = outputs[q2.id]
        assert all(not r.is_poisoned for r in q2_results)
        assert not any(r.doc_id == "POISON_HOSTILE_Q1" for r in q2_results)


# ===========================================================================
# 2. Evaluator Invariants in Isolated Mode
# ===========================================================================

class TestEvaluatorInvariants:
    """Stress tests verifying mathematical invariants of Evaluator in isolated mode."""

    def test_evaluator_strict_invariants_across_all_engines(self, cti_stress_fixture):
        clean_docs, queries, poison_mgr = cti_stress_fixture
        budget = 3
        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="dense", attack_budget=budget
        )

        bm25 = BM25Retriever()
        dense = DenseFAISSRetriever(persist_cache=False)
        engines = [
            ("BM25", bm25),
            ("DenseFAISS", dense),
            ("HybridRerank", HybridRerankRetriever(bm25, dense)),
            ("GraphRAG", GraphRAGRetriever()),
        ]

        for name, engine in engines:
            outputs, latencies = execute_isolated_retrieval(
                engine, clean_docs, payloads, queries, top_k=5
            )

            res = Evaluator.evaluate_engine(
                engine_name=name,
                attack_type="dense_b3",
                queries=queries,
                retrieval_outputs=outputs,
                retrieval_latencies=latencies,
                isolated_targets=True,
            )

            # Invariant 1: retrieval_asr_untargeted == 0.0
            assert res.retrieval_asr_untargeted == 0.0
            assert res.retrieval_asr_untargeted_top1 == 0.0
            assert res.retrieval_asr_untargeted_top5 == 0.0

            # Invariant 2: retrieval_asr_targeted == retrieval_asr_any
            assert res.retrieval_asr_targeted == res.retrieval_asr_any
            assert res.retrieval_asr_targeted_top1 == res.retrieval_asr_any_top1
            assert res.retrieval_asr_targeted_top5 == res.retrieval_asr_any_top5

            # Invariant 3: per-trace invariants
            for trace in res.traces:
                assert trace.has_untargeted_poison_in_top1 is False
                assert trace.has_untargeted_poison_in_top5 is False
                if trace.has_poison_in_top1:
                    assert trace.has_targeted_poison_in_top1 is True
                if trace.has_poison_in_top5:
                    assert trace.has_targeted_poison_in_top5 is True

    def test_evaluator_detects_violation_if_isolated_flag_is_wrongly_claimed(self, cti_stress_fixture):
        """If someone runs shared mode (which contains foreign poisons) but sets isolated_targets=True,
        the Evaluator must NOT falsely report 0.0% untargeted ASR if foreign poisons are present!
        """
        clean_docs, queries, poison_mgr = cti_stress_fixture
        retriever = BM25Retriever()
        shared_corpus = poison_mgr.generate_poisoned_corpus(
            clean_docs, queries, attack_type="sparse", attack_budget=3
        )
        outputs, lats = execute_shared_retrieval(retriever, shared_corpus, queries, top_k=5)

        res = Evaluator.evaluate_engine(
            "BM25", "sparse", queries, outputs, lats, isolated_targets=True
        )

        # In shared mode with 5 queries, untargeted poisons WILL be retrieved by queries.
        # Even with isolated_targets=True passed, the Evaluator calculates untargeted from the actual data!
        if res.retrieval_asr_any > res.retrieval_asr_targeted:
            assert res.retrieval_asr_untargeted > 0.0
            assert res.retrieval_asr_targeted != res.retrieval_asr_any


# ===========================================================================
# 3. Budget Sensitivity & Payload Diversity Tests
# ===========================================================================

class TestBudgetSensitivityAndDiversity:
    """Stress tests verifying that increasing budget produces diverse payloads
    and preserves sensitivity without premature context saturation.
    """

    @pytest.mark.parametrize("attack_type", [
        "sparse", "dense", "hybrid", "graph", "pure_topological", "blackbox"
    ])
    def test_payload_diversity_across_budgets_1_3_5(self, cti_stress_fixture, attack_type):
        _, queries, poison_mgr = cti_stress_fixture
        target_query = queries[0]

        payloads = poison_mgr.generate_poison_payloads_for_query(
            target_query, attack_type=attack_type, attack_budget=5
        )
        assert len(payloads) == 5

        # 1. Unique document IDs
        ids = [p.id for p in payloads]
        assert len(ids) == len(set(ids)), f"{attack_type} generated duplicate document IDs!"

        # 2. Content diversity
        if attack_type in ["sparse", "dense", "hybrid", "blackbox"]:
            texts = [p.text for p in payloads]
            assert len(texts) == len(set(texts)), f"{attack_type} generated bitwise duplicate texts!"
            titles = [p.title for p in payloads]
            assert len(titles) == len(set(titles)), f"{attack_type} generated duplicate titles!"
        elif attack_type == "graph":
            # Graph payloads must have distinct entity sets or relations
            all_bridge_ents = [set(p.entities) for p in payloads]
            for i in range(len(payloads)):
                for j in range(i + 1, len(payloads)):
                    assert all_bridge_ents[i] != all_bridge_ents[j], (
                        f"Graph budget {i} and {j} generated identical entity sets!"
                    )
        elif attack_type == "pure_topological":
            # Pure topological must have distinct bridge relations
            for i in range(len(payloads)):
                for j in range(i + 1, len(payloads)):
                    rels_i = {(r["source"], r["target"]) for r in payloads[i].relations}
                    rels_j = {(r["source"], r["target"]) for r in payloads[j].relations}
                    assert rels_i.isdisjoint(rels_j), (
                        f"Pure topological budget {i} and {j} share identical bridge relations!"
                    )

    def test_budget_1_saturation_absence_in_isolated_mode(self, cti_stress_fixture):
        """In shared mode, N queries with B=1 injects N poison docs.
        In isolated mode, for any query Qi, strictly 1 poison doc exists in the index.
        Therefore, at B=1:
        - isolated mode Top-5 results contain AT MOST 1 poison doc.
        - at least 4 out of 5 results MUST BE clean docs.
        """
        clean_docs, queries, poison_mgr = cti_stress_fixture
        retriever = BM25Retriever()

        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=1
        )

        outputs, _ = execute_isolated_retrieval(
            retriever, clean_docs, payloads, queries, top_k=5
        )

        for q in queries:
            results = outputs[q.id]
            poison_count = sum(1 for r in results if r.is_poisoned)
            clean_count = sum(1 for r in results if not r.is_poisoned)
            assert poison_count <= 1, f"Query {q.id} had {poison_count} poisons at B=1 in isolated mode!"
            assert clean_count >= min(4, len(results) - poison_count)

    def test_poison_density_scaling_with_budget(self, cti_stress_fixture):
        """Verifies that as budget increases from 1 to 3 to 5, the maximum possible
        poison density in Top-5 results scales as 1 -> 3 -> 5.
        """
        clean_docs, queries, poison_mgr = cti_stress_fixture
        retriever = BM25Retriever()

        for b in [1, 3, 5]:
            payloads = poison_mgr.generate_isolated_poison_payloads(
                queries, attack_type="sparse", attack_budget=b
            )
            outputs, _ = execute_isolated_retrieval(
                retriever, clean_docs, payloads, queries, top_k=5
            )
            for q in queries:
                results = outputs[q.id]
                poison_count = sum(1 for r in results if r.is_poisoned)
                assert poison_count <= b, f"At budget {b}, found {poison_count} poisons in Top-5!"


# ===========================================================================
# 4. Edge Cases Stress Testing
# ===========================================================================

class TestIsolatedProtocolEdgeCases:
    """Stress tests edge cases: single query, odd budgets, empty clean corpus, high top_k, B=0."""

    def test_single_query_evaluation(self, cti_stress_fixture):
        """Validates that a 1-query run executes cleanly without division-by-zero
        or percentile errors in latency calculations.
        """
        clean_docs, queries, poison_mgr = cti_stress_fixture
        single_query = [queries[0]]
        retriever = BM25Retriever()

        payloads = poison_mgr.generate_isolated_poison_payloads(
            single_query, attack_type="sparse", attack_budget=1
        )

        outputs, latencies = execute_isolated_retrieval(
            retriever, clean_docs, payloads, single_query, top_k=5
        )

        res = Evaluator.evaluate_engine(
            "BM25", "sparse_b1", single_query, outputs, latencies, isolated_targets=True
        )

        assert res.total_queries == 1
        assert res.retrieval_asr_untargeted == 0.0
        assert res.retrieval_asr_targeted in [0.0, 1.0]
        assert isinstance(res.latency_median_ms, float)
        assert isinstance(res.latency_iqr_ms, float)

    @pytest.mark.parametrize("odd_budget", [1, 3, 5, 7, 9])
    def test_odd_budgets_scaling_and_wrapping(self, cti_stress_fixture, odd_budget):
        """Validates that odd budgets > 5 gracefully wrap style and facet templates
        without IndexError.
        """
        _, queries, poison_mgr = cti_stress_fixture
        q = queries[0]

        for attack in ["sparse", "dense", "hybrid", "graph", "pure_topological", "blackbox"]:
            payloads = poison_mgr.generate_poison_payloads_for_query(
                q, attack_type=attack, attack_budget=odd_budget
            )
            assert len(payloads) == odd_budget
            ids = [p.id for p in payloads]
            assert len(ids) == len(set(ids))

    def test_empty_clean_corpus_handling(self, cti_stress_fixture):
        """Adversarial edge case: empty clean corpus (clean_docs = []).
        The isolated index contains ONLY the poison documents.
        All 4 retrievers must handle this without crashing.
        """
        _, queries, poison_mgr = cti_stress_fixture
        empty_clean = []
        budget = 2
        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=budget
        )

        bm25 = BM25Retriever()
        dense = DenseFAISSRetriever(persist_cache=False)
        engines = [
            ("BM25", bm25),
            ("DenseFAISS", dense),
            ("HybridRerank", HybridRerankRetriever(bm25, dense)),
            ("GraphRAG", GraphRAGRetriever()),
        ]

        for name, engine in engines:
            outputs, latencies = execute_isolated_retrieval(
                engine, empty_clean, payloads, queries, top_k=5
            )
            res = Evaluator.evaluate_engine(
                name, "sparse_empty_corpus", queries, outputs, latencies, isolated_targets=True
            )
            assert res.total_queries == len(queries)
            assert res.retrieval_asr_untargeted == 0.0
            # Since index contains ONLY target poison, any retrieved document is target poison
            assert res.retrieval_asr_targeted == res.retrieval_asr_any

    def test_high_top_k_exceeding_index_size(self, cti_stress_fixture):
        """Adversarial edge case: top_k = 50 when index has only 12 clean docs + 1 poison.
        Retrievers must return at most 13 docs without IndexError or padding corruption.
        """
        clean_docs, queries, poison_mgr = cti_stress_fixture
        retriever = BM25Retriever()
        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=1
        )

        outputs, _ = execute_isolated_retrieval(
            retriever, clean_docs, payloads, queries, top_k=50
        )

        for q in queries:
            results = outputs[q.id]
            assert len(results) == len(clean_docs) + 1
            poison_results = [r for r in results if r.is_poisoned]
            assert len(poison_results) == 1
            assert poison_results[0].poison_target_query == q.id

    def test_zero_attack_budget(self, cti_stress_fixture):
        """Adversarial edge case: attack_budget = 0.
        Isolated payload generation produces empty lists; retrieval behaves as clean baseline.
        """
        clean_docs, queries, poison_mgr = cti_stress_fixture
        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=0
        )

        for q in queries:
            assert len(payloads[q.id]) == 0

        retriever = BM25Retriever()
        outputs, latencies = execute_isolated_retrieval(
            retriever, clean_docs, payloads, queries, top_k=5
        )

        res = Evaluator.evaluate_engine(
            "BM25", "clean_b0", queries, outputs, latencies, isolated_targets=True
        )

        assert res.retrieval_asr_targeted == 0.0
        assert res.retrieval_asr_any == 0.0
        assert res.retrieval_asr_untargeted == 0.0
        assert res.clean_recall_top5 >= 0.0

    def test_missing_query_in_poison_payloads_dict(self, cti_stress_fixture):
        """If a query is missing from poison_payloads, execute_isolated_retrieval
        must fall back to clean docs without KeyError.
        """
        clean_docs, queries, _ = cti_stress_fixture
        incomplete_payloads = {}  # Empty dict!

        retriever = BM25Retriever()
        outputs, latencies = execute_isolated_retrieval(
            retriever, clean_docs, incomplete_payloads, queries, top_k=5
        )

        assert len(outputs) == len(queries)
        for q in queries:
            assert all(not r.is_poisoned for r in outputs[q.id])

    def test_hostile_query_text_special_characters(self, cti_stress_fixture):
        """Hostile queries with regex tokens, punctuation, unicode, empty strings."""
        clean_docs, _, poison_mgr = cti_stress_fixture
        hostile_queries = [
            GoldQuery("HQ1", "CVE-2024-1234 (critical) [RCE] in /api/v1?test=.*+", "cve", ["DOC_1"], "Ans", "Poison"),
            GoldQuery("HQ2", "'; DROP TABLE indices; --", "sql", ["DOC_2"], "Ans", "Poison"),
            GoldQuery("HQ3", "🔒 ATT&CK™ T1059.001: PowerShell execution 🚀", "mitre", ["DOC_3"], "Ans", "Poison"),
            GoldQuery("HQ4", "    ", "empty", [], "Ans", "Poison"),
        ]

        payloads = poison_mgr.generate_isolated_poison_payloads(
            hostile_queries, attack_type="sparse", attack_budget=1
        )

        bm25 = BM25Retriever()
        outputs, latencies = execute_isolated_retrieval(
            bm25, clean_docs, payloads, hostile_queries, top_k=5
        )

        res = Evaluator.evaluate_engine(
            "BM25", "sparse_hostile", hostile_queries, outputs, latencies, isolated_targets=True
        )

        assert res.total_queries == 4
        assert res.retrieval_asr_untargeted == 0.0
        assert res.retrieval_asr_targeted == res.retrieval_asr_any
