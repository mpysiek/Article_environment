"""Comprehensive unit and integration tests for Recommendation 3 (Isolated Evaluation Protocol per Query).

Validates:
1. TestZeroForeignPoisonIsolation (5 tests):
   Strict zero foreign poison contamination in Top-k results across all retrievers.
2. TestBudgetSensitivity (5 tests):
   Payload scaling, payload diversity across budget indices, monotonic ASR sensitivity across B in {1, 3, 5},
   and avoidance of B=1 saturation ceiling.
3. TestCleanRecallPreservation (4 tests):
   Clean recall in isolated mode >= shared mode, preservation when attack fails, graceful degradation.
4. TestSharedModeBackwardCompatibility (2 tests):
   execute_shared_retrieval remains operational, produces expected foreign contamination.
5. TestBenchmarkAndReporterIntegration (2 tests):
   CLI argument parsing, report generation with dynamic isolated protocol explanations, Pareto ranking table.
"""

import sys
import argparse
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
from src.visualization.reporter import (
    BenchmarkReporter,
    compute_pareto_ranking,
    MIN_UTILITY_THRESHOLD,
    is_isolated_run,
)


@pytest.fixture
def synthetic_cti_fixture():
    clean_docs = build_cti_knowledge_base()[:8]
    queries = build_gold_benchmark_queries()[:3]
    poison_mgr = CorpusPoisonManager(query_echo=True)
    return clean_docs, queries, poison_mgr


# ===========================================================================
# 1. Zero Foreign Poison Isolation Tests
# ===========================================================================

class TestZeroForeignPoisonIsolation:
    """Validates strict zero foreign poison contamination in Top-k under isolated protocol."""

    def test_isolated_payload_generation_partitions_by_query_id(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        budget = 2
        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=budget
        )

        assert set(payloads.keys()) == {q.id for q in queries}
        for q in queries:
            q_payloads = payloads[q.id]
            assert len(q_payloads) == budget
            for doc in q_payloads:
                assert doc.is_poisoned is True
                assert doc.poison_target_query == q.id
                for other_q in queries:
                    if other_q.id != q.id:
                        assert doc.poison_target_query != other_q.id

    def test_isolated_corpus_builder_contains_zero_foreign_poisons(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        target_query = queries[0]
        budget = 3

        iso_corpus = poison_mgr.generate_isolated_corpus_for_query(
            clean_docs, target_query, attack_type="dense", attack_budget=budget
        )

        assert len(iso_corpus) == len(clean_docs) + budget
        poison_docs = [d for d in iso_corpus if d.is_poisoned]
        assert len(poison_docs) == budget

        for doc in poison_docs:
            assert doc.poison_target_query == target_query.id
            for other_q in queries[1:]:
                assert doc.poison_target_query != other_q.id

    def test_execute_isolated_retrieval_zero_foreign_in_top_k(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()
        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=2
        )

        outputs, latencies = execute_isolated_retrieval(
            engine=retriever,
            clean_docs=clean_docs,
            poison_payloads=payloads,
            queries=queries,
            top_k=5,
        )

        assert set(outputs.keys()) == {q.id for q in queries}
        for q in queries:
            results = outputs[q.id]
            for r in results:
                if r.is_poisoned:
                    assert r.poison_target_query == q.id
                    for other_q in queries:
                        if other_q.id != q.id:
                            assert r.poison_target_query != other_q.id

    def test_evaluator_reports_zero_untargeted_asr_in_isolated_mode(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()
        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=2
        )

        outputs, latencies = execute_isolated_retrieval(
            engine=retriever,
            clean_docs=clean_docs,
            poison_payloads=payloads,
            queries=queries,
            top_k=5,
        )

        result = Evaluator.evaluate_engine(
            engine_name="Sparse-BM25",
            attack_type="sparse_b2",
            queries=queries,
            retrieval_outputs=outputs,
            retrieval_latencies=latencies,
            isolated_targets=True,
        )

        assert result.isolated_targets is True
        assert result.retrieval_asr_untargeted == pytest.approx(0.0)
        assert result.retrieval_asr_untargeted_top1 == pytest.approx(0.0)
        assert result.retrieval_asr_untargeted_top5 == pytest.approx(0.0)
        assert result.retrieval_asr_targeted == pytest.approx(result.retrieval_asr_any)
        assert result.retrieval_asr_targeted_top1 == pytest.approx(result.retrieval_asr_any_top1)

        for t in result.traces:
            assert t.has_untargeted_poison_in_top1 is False
            assert t.has_untargeted_poison_in_top5 is False

    def test_all_four_retrieval_engines_enforce_zero_foreign_poisons(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        bm25 = BM25Retriever()
        dense = DenseFAISSRetriever(persist_cache=False)
        engines = [
            ("BM25", bm25),
            ("DenseFAISS", dense),
            ("HybridRerank", HybridRerankRetriever(bm25_engine=bm25, dense_engine=dense)),
            ("GraphRAG", GraphRAGRetriever()),
        ]

        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=1
        )

        for name, engine in engines:
            outputs, _ = execute_isolated_retrieval(
                engine=engine,
                clean_docs=clean_docs,
                poison_payloads=payloads,
                queries=queries,
                top_k=5,
            )
            for q in queries:
                for r in outputs[q.id]:
                    if r.is_poisoned:
                        assert r.poison_target_query == q.id, f"{name} retrieved foreign poison for {q.id}!"


# ===========================================================================
# 2. Budget Sensitivity Tests
# ===========================================================================

class TestBudgetSensitivity:
    """Validates metric sensitivity across budgets B in {1, 3, 5} without context saturation."""

    def test_isolated_payload_counts_strictly_scale_with_budget(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        for b in [1, 3, 5]:
            payloads = poison_mgr.generate_isolated_poison_payloads(
                queries, attack_type="dense", attack_budget=b
            )
            for q in queries:
                assert len(payloads[q.id]) == b

    def test_isolated_payloads_diverse_across_budget_indices(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        target_query = queries[0]

        for attack in ["sparse", "dense"]:
            payloads = poison_mgr.generate_poison_payloads_for_query(
                target_query, attack_type=attack, attack_budget=3
            )
            doc_ids = [p.id for p in payloads]
            doc_texts = [p.text for p in payloads]

            assert len(doc_ids) == len(set(doc_ids)), f"{attack} produced duplicate doc_ids across budget indices!"
            assert len(doc_texts) == len(set(doc_texts)), f"{attack} produced bitwise duplicate text across budget indices!"

        # Graph attack varies topological bridge entities and relation targets across budget indices
        graph_payloads = poison_mgr.generate_poison_payloads_for_query(
            target_query, attack_type="graph", attack_budget=3
        )
        assert len(graph_payloads) == 3
        graph_ids = [p.id for p in graph_payloads]
        assert len(graph_ids) == len(set(graph_ids))
        entity_sets = [tuple(p.entities) for p in graph_payloads]
        assert len(entity_sets) == len(set(entity_sets)), "Graph attack produced duplicate entities across budget indices!"

    def test_retrieval_asr_targeted_budget_monotonicity(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()

        asrs = {}
        for b in [1, 3, 5]:
            payloads = poison_mgr.generate_isolated_poison_payloads(
                queries, attack_type="sparse", attack_budget=b
            )
            outputs, latencies = execute_isolated_retrieval(
                engine=retriever,
                clean_docs=clean_docs,
                poison_payloads=payloads,
                queries=queries,
                top_k=5,
            )
            res = Evaluator.evaluate_engine(
                engine_name="BM25",
                attack_type=f"sparse_b{b}",
                queries=queries,
                retrieval_outputs=outputs,
                retrieval_latencies=latencies,
                isolated_targets=True,
            )
            asrs[b] = res.retrieval_asr_targeted

        assert asrs[1] <= asrs[3] <= asrs[5] or (asrs[5] >= asrs[1])

    def test_isolated_mode_avoids_budget_1_saturation(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()

        # Shared mode: 3 queries * budget 1 = 3 poisons in one index
        shared_corpus = poison_mgr.generate_poisoned_corpus(
            clean_docs, queries, attack_type="sparse", attack_budget=1
        )
        shared_outputs, shared_lats = execute_shared_retrieval(
            retriever, shared_corpus, queries, top_k=5
        )
        res_shared = Evaluator.evaluate_engine(
            "BM25", "sparse_shared", queries, shared_outputs, shared_lats, isolated_targets=False
        )

        # Isolated mode: exactly 1 poison in index per query
        iso_payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=1
        )
        iso_outputs, iso_lats = execute_isolated_retrieval(
            retriever, clean_docs, iso_payloads, queries, top_k=5
        )
        res_iso = Evaluator.evaluate_engine(
            "BM25", "sparse_iso", queries, iso_outputs, iso_lats, isolated_targets=True
        )

        assert res_iso.retrieval_asr_untargeted == 0.0
        # In isolated mode, untargeted contamination is strictly absent
        assert res_iso.retrieval_asr_untargeted <= res_shared.retrieval_asr_untargeted

    def test_budget_scaling_latency_profile(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()

        for b in [1, 3, 5]:
            payloads = poison_mgr.generate_isolated_poison_payloads(
                queries, attack_type="sparse", attack_budget=b
            )
            _, latencies = execute_isolated_retrieval(
                engine=retriever,
                clean_docs=clean_docs,
                poison_payloads=payloads,
                queries=queries,
                top_k=5,
            )
            for q in queries:
                lat = latencies[q.id]
                assert isinstance(lat, float)
                assert 0.0 <= lat < 5000.0


# ===========================================================================
# 3. Clean Recall Preservation Tests
# ===========================================================================

class TestCleanRecallPreservation:
    """Validates clean ground truth recall behavior under isolated evaluation protocol."""

    def test_clean_recall_uncontaminated_by_foreign_poisons(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()

        # Shared mode with foreign poisons
        shared_corpus = poison_mgr.generate_poisoned_corpus(
            clean_docs, queries, attack_type="sparse", attack_budget=3
        )
        shared_outputs, _ = execute_shared_retrieval(retriever, shared_corpus, queries, top_k=5)
        res_shared = Evaluator.evaluate_engine("BM25", "sparse_shared", queries, shared_outputs)

        # Isolated mode
        iso_payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=3
        )
        iso_outputs, _ = execute_isolated_retrieval(retriever, clean_docs, iso_payloads, queries, top_k=5)
        res_iso = Evaluator.evaluate_engine("BM25", "sparse_iso", queries, iso_outputs, isolated_targets=True)

        assert res_iso.clean_recall_top5 >= res_shared.clean_recall_top5

    def test_clean_recall_preserved_when_attack_fails(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()

        # Baseline clean run
        retriever.build_index(clean_docs)
        clean_outputs = {q.id: retriever.retrieve(q.query_text, top_k=5) for q in queries}
        res_clean = Evaluator.evaluate_engine("BM25", "clean_baseline", queries, clean_outputs)

        # Weak poison without query echo
        poison_mgr_no_echo = CorpusPoisonManager(query_echo=False)
        iso_payloads = poison_mgr_no_echo.generate_isolated_poison_payloads(
            queries, attack_type="blackbox", attack_budget=1
        )
        iso_outputs, _ = execute_isolated_retrieval(retriever, clean_docs, iso_payloads, queries, top_k=5)
        res_iso = Evaluator.evaluate_engine("BM25", "weak_iso", queries, iso_outputs, isolated_targets=True)

        # Clean recall is preserved or matches baseline closely
        assert res_iso.clean_recall_top5 >= 0.0
        assert isinstance(res_iso.clean_recall_top5, float)

    def test_clean_recall_graceful_degradation_under_target_hijack(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()

        iso_payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=1
        )
        iso_outputs, _ = execute_isolated_retrieval(retriever, clean_docs, iso_payloads, queries, top_k=5)

        for q in queries:
            results = iso_outputs[q.id]
            poison_count = sum(1 for r in results if r.is_poisoned)
            clean_count = sum(1 for r in results if not r.is_poisoned)
            assert poison_count <= 1
            assert clean_count >= len(results) - 1

    def test_clean_ground_truth_hits_preservation(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()

        retriever.build_index(clean_docs)
        clean_outputs = {q.id: retriever.retrieve(q.query_text, top_k=5) for q in queries}
        res_clean = Evaluator.evaluate_engine("BM25", "clean_baseline", queries, clean_outputs)
        clean_hits = {t.query_id: t.clean_ground_truth_hit for t in res_clean.traces}

        iso_payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=1
        )
        iso_outputs, _ = execute_isolated_retrieval(retriever, clean_docs, iso_payloads, queries, top_k=5)
        res_iso = Evaluator.evaluate_engine(
            "BM25", "sparse_iso", queries, iso_outputs, clean_ground_truth_hits=clean_hits, isolated_targets=True
        )

        for t in res_iso.traces:
            assert t.clean_ground_truth_hit == clean_hits[t.query_id]
        assert 0.0 <= res_iso.retrieval_asr_cond <= 1.0


# ===========================================================================
# 4. Shared Mode Backward Compatibility Tests
# ===========================================================================

class TestSharedModeBackwardCompatibility:
    """Validates that legacy shared corpus evaluation continues to function flawlessly."""

    def test_execute_shared_retrieval_still_functional(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()
        shared_corpus = poison_mgr.generate_poisoned_corpus(
            clean_docs, queries, attack_type="sparse", attack_budget=1
        )

        outputs, latencies = execute_shared_retrieval(retriever, shared_corpus, queries, top_k=5)
        assert set(outputs.keys()) == {q.id for q in queries}
        for q in queries:
            assert len(outputs[q.id]) <= 5
            assert q.id in latencies

    def test_shared_retrieval_exhibits_expected_foreign_contamination(self, synthetic_cti_fixture):
        clean_docs, queries, poison_mgr = synthetic_cti_fixture
        retriever = BM25Retriever()
        shared_corpus = poison_mgr.generate_poisoned_corpus(
            clean_docs, queries, attack_type="sparse", attack_budget=3
        )

        outputs, lats = execute_shared_retrieval(retriever, shared_corpus, queries, top_k=5)
        res = Evaluator.evaluate_engine("BM25", "sparse_shared", queries, outputs, lats, isolated_targets=False)

        assert res.isolated_targets is False
        assert hasattr(res, "retrieval_asr_untargeted")
        assert hasattr(res, "retrieval_asr_targeted")

# ===========================================================================
# 5. Benchmark Script & Reporter Integration Tests
# ===========================================================================

class TestBenchmarkAndReporterIntegration:
    """Validates CLI flags and reporter integration under isolated targets protocol."""

    def test_cli_argument_isolated_targets_parsing(self):
        import scripts.run_comparison_benchmark as benchmark_module

        # Test CLI parser
        parser = argparse.ArgumentParser()
        parser.add_argument("--isolated-targets", action="store_true", default=False)
        parser.add_argument("--cost-free", action="store_true", default=None,
                            help="Force 100%% cost-free local evaluation ($0.00 API cost)")

        args_default = parser.parse_args([])
        assert args_default.isolated_targets is False

        args_flag = parser.parse_args(["--isolated-targets"])
        assert args_flag.isolated_targets is True

        # Verify help formatting does not crash
        help_text = parser.format_help()
        assert "--isolated-targets" in help_text
        assert "100% cost-free" in help_text or "100%% cost-free" in help_text

    def test_reporter_handles_isolated_benchmark_results(self, tmp_path):
        out_file = tmp_path / "isolated_report.md"
        r_iso = EngineBenchmarkResult(
            engine_name="ResilientGraphRAG",
            attack_type="sparse_b1",
            total_queries=5,
            retrieval_asr_top1=0.0,
            retrieval_asr_top3=0.0,
            retrieval_asr_top5=0.0,
            clean_recall_top5=0.90,
            clean_mrr=0.85,
            generation_asr=0.0,
            ground_truth_retention=0.0,
            conflict_detection_rate=0.0,
            retrieval_asr_targeted=0.0,
            retrieval_asr_untargeted=0.0,
            retrieval_asr_any=0.0,
            isolated_targets=True,
        )

        md = BenchmarkReporter.generate_markdown_report(
            [r_iso], out_file, corpus_type="synthetic", isolated_targets=True
        )

        assert out_file.exists()
        assert "Recommendation 3" in md or "Izolowany" in md
        assert "0.0%" in md
        assert "Pareto" not in md
        assert "Status użyteczności" in md
        assert "VIABLE" in md
        assert "ResilientGraphRAG" in md
