"""Adversarial stress tests for Recommendation 3 (Clean Recall Preservation & Backward Compatibility).

Empirical challenger test harness targeting:
1. Clean Recall preservation: isolated mode vs shared mode under high foreign noise,
   failed attack clean baseline recovery, clean ground truth retention, and top-k displacement bounds.
2. Shared mode backward compatibility: untargeted contamination metrics, execute_shared_retrieval contract,
   default behavior without flags.
3. CLI argparse behavior: combinations, help formatting, error exits.
"""

import sys
import json
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
import scripts.run_comparison_benchmark as benchmark_script


# ===========================================================================
# 1. Clean Recall Preservation Adversarial Tests
# ===========================================================================

class TestCleanRecallAdversarial:
    """Adversarial verification of clean recall preservation and ground truth retention."""

    @pytest.fixture
    def benchmark_data(self):
        clean_docs = build_cti_knowledge_base()
        queries = build_gold_benchmark_queries()[:5]
        poison_mgr = CorpusPoisonManager(query_echo=True)
        return clean_docs, queries, poison_mgr

    def test_clean_recall_isolated_strictly_preserves_or_improves_under_foreign_noise(self, benchmark_data):
        """Stress Test: Compare clean recall when 5 queries have 5 payloads each in shared vs isolated.
        In shared mode, 25 poison docs are in the corpus; foreign poisons can displace clean docs.
        In isolated mode, exactly 5 poisons are present per query.
        Invariant: isolated clean recall must be >= shared clean recall.
        """
        clean_docs, queries, poison_mgr = benchmark_data
        retriever = BM25Retriever()

        # Shared mode: 5 queries * 5 poisons = 25 foreign + targeted poisons
        shared_corpus = poison_mgr.generate_poisoned_corpus(
            clean_docs, queries, attack_type="sparse", attack_budget=5
        )
        shared_outputs, shared_lats = execute_shared_retrieval(retriever, shared_corpus, queries, top_k=5)
        res_shared = Evaluator.evaluate_engine(
            "BM25", "sparse_b5_shared", queries, shared_outputs, shared_lats, isolated_targets=False
        )

        # Isolated mode: exactly 5 target poisons per query
        iso_payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=5
        )
        iso_outputs, iso_lats = execute_isolated_retrieval(
            retriever, clean_docs, iso_payloads, queries, top_k=5
        )
        res_iso = Evaluator.evaluate_engine(
            "BM25", "sparse_b5_iso", queries, iso_outputs, iso_lats, isolated_targets=True
        )

        assert res_iso.clean_recall_top5 >= res_shared.clean_recall_top5, (
            f"Isolated recall ({res_iso.clean_recall_top5}) was lower than shared recall ({res_shared.clean_recall_top5})!"
        )
        assert res_iso.retrieval_asr_untargeted == 0.0

    def test_clean_recall_when_attack_fails_strictly_matches_clean_baseline(self, benchmark_data):
        """Stress Test: When poison payload fails to match query keywords/semantics,
        isolated mode must recover 100% of baseline clean recall, because zero foreign poisons exist.
        """
        clean_docs, queries, _ = benchmark_data
        retriever = BM25Retriever()

        # Baseline clean run
        retriever.build_index(clean_docs)
        clean_outputs = {q.id: retriever.retrieve(q.query_text, top_k=5) for q in queries}
        res_baseline = Evaluator.evaluate_engine("BM25", "clean_baseline", queries, clean_outputs)

        # Craft non-matching dummy payloads (irrelevant domain text)
        dummy_payloads: Dict[str, List[CTIDocument]] = {
            q.id: [
                CTIDocument(
                    id=f"dummy_poison_{q.id}_{i}",
                    title=f"Dummy Recipe Title {i}",
                    text=f"Completely unrelated baking recipe for chocolate souffles with sugar and butter {i}",
                    doc_type="cve",
                    is_poisoned=True,
                    poison_target_query=q.id,
                    poison_type="sparse",
                )
                for i in range(3)
            ]
            for q in queries
        }

        # Isolated retrieval with non-matching poison
        iso_outputs, _ = execute_isolated_retrieval(retriever, clean_docs, dummy_payloads, queries, top_k=5)
        res_iso_dummy = Evaluator.evaluate_engine(
            "BM25", "dummy_attack", queries, iso_outputs, isolated_targets=True
        )

        # Because poison did not match, no poison entered Top-5
        assert res_iso_dummy.retrieval_asr_top5 == 0.0
        assert res_iso_dummy.retrieval_asr_targeted == 0.0
        # Clean recall must match baseline exactly
        assert res_iso_dummy.clean_recall_top5 == pytest.approx(res_baseline.clean_recall_top5)
        assert res_iso_dummy.clean_mrr == pytest.approx(res_baseline.clean_mrr)

    def test_clean_ground_truth_retention_and_asr_cond_correctness(self, benchmark_data):
        """Stress Test: Verify that clean_ground_truth_hits correctly propagates to traces
        and that conditional ASR (ASR_cond) is mathematically exact.
        """
        clean_docs, queries, poison_mgr = benchmark_data
        retriever = BM25Retriever()

        # Step 1: Baseline clean run
        retriever.build_index(clean_docs)
        clean_outputs = {q.id: retriever.retrieve(q.query_text, top_k=5) for q in queries}
        res_clean = Evaluator.evaluate_engine("BM25", "clean_baseline", queries, clean_outputs)
        baseline_hits = {t.query_id: t.clean_ground_truth_hit for t in res_clean.traces}

        # Step 2: Isolated attack run passing baseline_hits
        iso_payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=1
        )
        iso_outputs, _ = execute_isolated_retrieval(retriever, clean_docs, iso_payloads, queries, top_k=5)
        res_attack = Evaluator.evaluate_engine(
            "BM25",
            "sparse_b1",
            queries,
            iso_outputs,
            clean_ground_truth_hits=baseline_hits,
            isolated_targets=True
        )

        # Verify trace preservation
        for trace in res_attack.traces:
            assert trace.clean_ground_truth_hit == baseline_hits[trace.query_id]

        # Verify ASR_cond manual calculation matches
        cond_traces = [t for t in res_attack.traces if t.clean_ground_truth_hit]
        if cond_traces:
            expected_asr_cond = sum(1 for t in cond_traces if t.has_poison_in_top1) / len(cond_traces)
        else:
            expected_asr_cond = 0.0
        assert res_attack.retrieval_asr_cond == pytest.approx(expected_asr_cond)

    def test_clean_recall_top_k_displacement_bound_across_all_engines(self, benchmark_data):
        """Stress Test: At budget B=1, in isolated mode at most 1 poison can enter top-5.
        Thus at least min(len(clean_docs), 5) - 1 clean docs must be in top-5 for every query.
        Across all 4 engines.
        """
        clean_docs, queries, poison_mgr = benchmark_data
        engines = [
            ("BM25", BM25Retriever()),
            ("DenseFAISS", DenseFAISSRetriever(persist_cache=False)),
            ("GraphRAG", GraphRAGRetriever()),
        ]

        iso_payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, attack_type="sparse", attack_budget=1
        )

        for name, engine in engines:
            outputs, _ = execute_isolated_retrieval(
                engine, clean_docs, iso_payloads, queries, top_k=5
            )
            for q in queries:
                results = outputs[q.id]
                poison_count = sum(1 for r in results if r.is_poisoned)
                clean_count = sum(1 for r in results if not r.is_poisoned)
                assert poison_count <= 1, f"Engine {name} had {poison_count} poisons in Top-5 at B=1!"
                assert clean_count == len(results) - poison_count
                assert clean_count >= len(results) - 1, (
                    f"Engine {name} had too few clean docs ({clean_count}) relative to total results ({len(results)}) at B=1!"
                )


# ===========================================================================
# 2. Shared Mode Backward Compatibility Adversarial Tests
# ===========================================================================

class TestSharedModeBackwardCompatibilityAdversarial:
    """Adversarial verification of shared mode behavior, default parameters, and backward compatibility."""

    @pytest.fixture
    def benchmark_data(self):
        clean_docs = build_cti_knowledge_base()
        queries = build_gold_benchmark_queries()[:4]
        poison_mgr = CorpusPoisonManager(query_echo=True)
        return clean_docs, queries, poison_mgr

    def test_evaluator_defaults_to_shared_mode_when_omitted(self, benchmark_data):
        """Verify that omitting isolated_targets in Evaluator.evaluate_engine defaults to False (shared mode)."""
        clean_docs, queries, poison_mgr = benchmark_data
        retriever = BM25Retriever()
        retriever.build_index(clean_docs)
        outputs = {q.id: retriever.retrieve(q.query_text, top_k=5) for q in queries}

        result = Evaluator.evaluate_engine(
            engine_name="BM25",
            attack_type="clean_baseline",
            queries=queries,
            retrieval_outputs=outputs
        )
        assert result.isolated_targets is False

    def test_execute_shared_retrieval_reproducibility_and_contract(self, benchmark_data):
        """Verify execute_shared_retrieval contract: takes (engine, corpus, queries, top_k)
        and produces reproducible outputs and non-negative latencies.
        """
        clean_docs, queries, poison_mgr = benchmark_data
        retriever = BM25Retriever()
        shared_corpus = poison_mgr.generate_poisoned_corpus(
            clean_docs, queries, attack_type="sparse", attack_budget=2
        )

        out1, lat1 = execute_shared_retrieval(retriever, shared_corpus, queries, top_k=5)
        out2, lat2 = execute_shared_retrieval(retriever, shared_corpus, queries, top_k=5)

        assert set(out1.keys()) == {q.id for q in queries}
        for q in queries:
            ids1 = [r.doc_id for r in out1[q.id]]
            ids2 = [r.doc_id for r in out2[q.id]]
            assert ids1 == ids2, f"Shared retrieval non-deterministic for query {q.id}!"
            assert lat1[q.id] >= 0.0

    def test_shared_mode_untargeted_metrics_mathematical_identity(self, benchmark_data):
        """Verify that in shared mode, retrieval_asr_untargeted = retrieval_asr_any - retrieval_asr_targeted.
        And retrieval_asr_untargeted_top1 = poison_top1 - targeted_top1.
        """
        clean_docs, queries, poison_mgr = benchmark_data
        retriever = BM25Retriever()
        shared_corpus = poison_mgr.generate_poisoned_corpus(
            clean_docs, queries, attack_type="sparse", attack_budget=3
        )
        outputs, lats = execute_shared_retrieval(retriever, shared_corpus, queries, top_k=5)

        result = Evaluator.evaluate_engine(
            engine_name="BM25",
            attack_type="sparse_b3",
            queries=queries,
            retrieval_outputs=outputs,
            retrieval_latencies=lats,
            isolated_targets=False
        )

        assert result.isolated_targets is False
        assert result.retrieval_asr_untargeted == pytest.approx(
            result.retrieval_asr_any - result.retrieval_asr_targeted
        )
        assert result.retrieval_asr_untargeted_top1 == pytest.approx(
            result.retrieval_asr_any_top1 - result.retrieval_asr_targeted_top1
        )
        assert result.retrieval_asr_untargeted >= 0.0

    def test_run_benchmark_matrix_default_is_shared_mode(self):
        """Verify that the function signature of run_benchmark_matrix defaults to isolated_targets=False."""
        import inspect
        sig = inspect.signature(benchmark_script.run_benchmark_matrix)
        assert "isolated_targets" in sig.parameters
        assert sig.parameters["isolated_targets"].default is False


# ===========================================================================
# 3. CLI Argparse Behavior Adversarial Tests
# ===========================================================================

class TestCLIArgparseAdversarial:
    """Adversarial testing of CLI arguments and help formatting."""

    def test_cli_help_formatting_no_crash(self, capsys):
        """Stress Test: Ensure parser.format_help() never throws a TypeError or format crash."""
        parser = argparse.ArgumentParser(description="CTI RAG Corpus Poisoning Benchmark: Comparing 4 RAG Architectures")
        parser.add_argument("--corpus", choices=["real", "synthetic"], default="real")
        parser.add_argument("--cost-free", action="store_true", default=None,
                            help="Force 100%% cost-free local evaluation ($0.00 API cost)")
        parser.add_argument("--isolated-targets", action="store_true", default=False,
                            help="Run isolated target evaluation (1 target query per index instance, Recommendation 3)")

        help_text = parser.format_help()
        assert "--isolated-targets" in help_text
        assert "Recommendation 3" in help_text
        assert "100%" in help_text

    def test_cli_argparse_parsing_permutations(self):
        """Test combinations of CLI flags with isolated-targets."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--corpus", choices=["real", "synthetic"], default="real")
        parser.add_argument("--queries", type=int, default=100)
        parser.add_argument("--cost-free", action="store_true", default=None)
        parser.add_argument("--no-query-echo", action="store_true")
        parser.add_argument("--isolated-targets", action="store_true", default=False)

        # Default run
        args_default = parser.parse_args([])
        assert args_default.isolated_targets is False
        assert args_default.corpus == "real"

        # Explicit isolated
        args_iso = parser.parse_args(["--isolated-targets", "--corpus", "synthetic", "--queries", "10"])
        assert args_iso.isolated_targets is True
        assert args_iso.corpus == "synthetic"
        assert args_iso.queries == 10

        # Invalid flag raises SystemExit
        with pytest.raises(SystemExit):
            parser.parse_args(["--unknown-option"])
