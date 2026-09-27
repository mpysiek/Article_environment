"""Tests for the v3 changes: full tie-group logging, the hybrid candidate pool, the v2/v3
query sets, the per-template constant-slot check (K4) and the corrected bridge threshold.

Each test pins one property the v3 manuscript relies on, so that a later refactor cannot
quietly change what the numbers mean.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.corpus.dataset import CTIDocument, GoldQuery, RetrievalResult
from src.evaluation.metrics import Evaluator, full_tie_bounds, candidate_pool_record
from src.evaluation.stages import deep_retrieve


def rr(doc_id, score, poison=False, meta=None):
    return RetrievalResult(doc_id=doc_id, score=score, rank=0, title=doc_id, text=doc_id,
                           is_poisoned=poison, doc_type="cve", metadata=dict(meta or {}))


def gq(qid, gold, category="cve_lookup", text=None):
    return GoldQuery(id=qid, query_text=text or f"question {qid}", category=category,
                     ground_truth_doc_ids=list(gold), ground_truth_answer="a",
                     target_poison_assertion="p", key_terms=list(gold))


# ------------------------------------------------------------------ full_tie_bounds

class TestFullTieBounds:
    def test_no_ties_gives_degenerate_bounds(self):
        ranking = [rr("POISON_A", 3.0, True), rr("C1", 2.0), rr("G", 1.5), rr("C2", 1.0),
                   rr("C3", 0.9), rr("C4", 0.8)]
        b = full_tie_bounds(ranking, {"G"}, top_k=5)
        assert b["tie_p1_lo"] and b["tie_p1_hi"]
        assert b["tie_hit_lo"] and b["tie_hit_hi"]
        assert b["tie_recall_lo"] == b["tie_recall_hi"] == 1.0
        assert b["rank1_tie_size"] == 1 and b["boundary_tie_size"] == 0
        assert b["gt_best_rank"] == 3 and b["poison_best_rank"] == 1

    def test_rank1_group_is_used_whole_not_only_ranks_1_and_2(self):
        # Ranks 1 and 2 are both clean, so a rank-1/rank-2 comparison sees no crossing tie;
        # the payload at rank 3 has the same score and could equally have been placed first.
        ranking = [rr("C1", 1.0), rr("C2", 1.0), rr("POISON_A", 1.0, True), rr("C3", 0.5),
                   rr("C4", 0.4), rr("C5", 0.3)]
        b = full_tie_bounds(ranking, {"C3"}, top_k=5)
        assert b["rank1_tie_size"] == 3
        assert b["tie_p1_lo"] is False and b["tie_p1_hi"] is True

    def test_boundary_group_competing_for_one_slot(self):
        # Four documents above the rank-5 score, three tied at it, one of them gold: the gold
        # document may or may not get the last slot.
        ranking = [rr("A", 5.0), rr("B", 4.0), rr("C", 3.0), rr("D", 2.0),
                   rr("X", 1.0), rr("G", 1.0), rr("Y", 1.0), rr("Z", 0.1)]
        b = full_tie_bounds(ranking, {"G"}, top_k=5)
        assert b["boundary_tie_size"] == 3
        assert b["tie_hit_lo"] is False and b["tie_hit_hi"] is True
        assert b["tie_recall_lo"] == 0.0 and b["tie_recall_hi"] == 1.0

    def test_boundary_group_that_must_include_gold(self):
        # Three above, two tied for two slots: both tied documents are in top-5 whatever the order.
        ranking = [rr("A", 5.0), rr("B", 4.0), rr("C", 3.0), rr("G", 1.0), rr("X", 1.0), rr("Z", 0.1)]
        b = full_tie_bounds(ranking, {"G"}, top_k=5)
        assert b["boundary_tie_size"] == 0
        assert b["tie_hit_lo"] is True and b["tie_hit_hi"] is True

    def test_poison_in_topk_bounds(self):
        ranking = [rr("A", 5.0), rr("B", 4.0), rr("C", 3.0), rr("D", 2.0),
                   rr("X", 1.0), rr("POISON_P", 1.0, True), rr("Z", 0.1)]
        b = full_tie_bounds(ranking, {"A"}, top_k=5)
        assert b["tie_pk_lo"] is False and b["tie_pk_hi"] is True

    def test_short_ranking_has_no_boundary_indeterminacy(self):
        ranking = [rr("G", 1.0), rr("X", 1.0), rr("POISON_P", 1.0, True)]
        b = full_tie_bounds(ranking, {"G"}, top_k=5)
        assert b["boundary_tie_size"] == 0
        assert b["tie_hit_lo"] and b["tie_hit_hi"]
        assert b["tie_pk_lo"] and b["tie_pk_hi"]
        assert b["tie_p1_lo"] is False and b["tie_p1_hi"] is True

    def test_empty_ranking(self):
        b = full_tie_bounds([], {"G"}, top_k=5)
        assert b["deep_depth"] == 0 and not b["tie_hit_hi"] and not b["tie_p1_hi"]


# ------------------------------------------------------------------ evaluator

class TestEvaluatorDeepOutputs:
    def _setup(self):
        q1 = gq("Q1", ["C3"])
        q2 = gq("Q2", ["G2"])
        # Q1: official ranks 1-2 tie between two clean documents; a payload ties at rank 3.
        deep1 = [rr("C1", 1.0), rr("C2", 1.0), rr("POISON_1", 1.0, True), rr("C3", 0.5),
                 rr("C4", 0.4), rr("C5", 0.3)]
        # Q2: gold at the rank-5 boundary in a three-way tie.
        deep2 = [rr("POISON_2", 9.0, True), rr("B", 4.0), rr("C", 3.0), rr("D", 2.0),
                 rr("G2", 1.0), rr("X", 1.0), rr("Y", 1.0), rr("Z", 0.1)]
        outputs = {"Q1": deep1[:5], "Q2": deep2[:5]}
        deep = {"Q1": deep1, "Q2": deep2}
        return [q1, q2], outputs, deep

    def test_point_metrics_do_not_depend_on_deep_outputs(self):
        queries, outputs, deep = self._setup()
        clean = {"Q1": True, "Q2": True}
        a = Evaluator.evaluate_engine("GraphRAG", "graph_b1", queries, outputs, clean_ground_truth_hits=clean)
        b = Evaluator.evaluate_engine("GraphRAG", "graph_b1", queries, outputs, clean_ground_truth_hits=clean,
                                      deep_outputs=deep)
        for f in ("retrieval_asr_top1", "retrieval_asr_top5", "retrieval_asr_cond",
                  "gt_displacement_rate", "clean_recall_top5", "clean_mrr"):
            assert getattr(a, f) == getattr(b, f), f
        assert [t.retrieved_doc_ids for t in a.traces] == [t.retrieved_doc_ids for t in b.traces]

    def test_full_group_bounds_replace_rank12_bounds(self):
        queries, outputs, deep = self._setup()
        clean = {"Q1": True, "Q2": True}
        r = Evaluator.evaluate_engine("GraphRAG", "graph_b1", queries, outputs,
                                      clean_ground_truth_hits=clean, deep_outputs=deep)
        assert r.tie_bounds_source == "full_group"
        # rank 1/2: Q1 is clean-clean (no crossing); Q2 has no rank-1 tie.
        assert r.poison_at_1_rank12_lower == r.poison_at_1_rank12_upper == 0.5
        # full group: Q1 could have put the payload first.
        assert r.poison_at_1_tie_lower == 0.5 and r.poison_at_1_tie_upper == 1.0
        assert r.n_top1_tie_crossing == 1
        # Q2's gold may fall out of top-5 under another ordering of the boundary tie.
        assert r.gt_displacement_rate == 0.0
        assert r.gt_displacement_tie_lower == 0.0 and r.gt_displacement_tie_upper == 0.5
        assert r.poison_at_1_cond_tie_lower == 0.5 and r.poison_at_1_cond_tie_upper == 1.0
        assert r.gt_hit_tie_lower == 0.5 and r.gt_hit_tie_upper == 1.0
        assert r.n_boundary_tie == 1 and r.n_deep_mismatch == 0
        t1, t2 = r.traces
        assert t1.tie_logged and t1.rank1_tie_size == 3 and t1.gt_best_rank == 4
        assert t2.boundary_tie_size == 3 and t2.retrieved_scores == [9.0, 4.0, 3.0, 2.0, 1.0]

    def test_partial_deep_outputs_fall_back_to_rank12(self):
        queries, outputs, deep = self._setup()
        del deep["Q2"]
        r = Evaluator.evaluate_engine("GraphRAG", "graph_b1", queries, outputs, deep_outputs=deep)
        assert r.tie_bounds_source == "rank12"
        assert r.gt_displacement_tie_lower is None and r.poison_at_5_tie_upper is None

    def test_deep_mismatch_is_counted(self):
        queries, outputs, deep = self._setup()
        deep["Q1"] = [deep["Q1"][1], deep["Q1"][0]] + deep["Q1"][2:]
        r = Evaluator.evaluate_engine("GraphRAG", "graph_b1", queries, outputs, deep_outputs=deep)
        assert r.n_deep_mismatch == 1 and r.traces[0].deep_mismatch

    def test_clean_baseline_has_zero_cond_bounds(self):
        queries, outputs, deep = self._setup()
        r = Evaluator.evaluate_engine("GraphRAG", "clean_baseline", queries, outputs, deep_outputs=deep)
        assert r.gt_displacement_tie_lower == 0.0 and r.gt_displacement_tie_upper == 0.0
        assert r.clean_recall_tie_lower == 0.5 and r.clean_recall_tie_upper == 1.0


# ------------------------------------------------------------------ deep_retrieve

class _RankingEngine:
    def __init__(self, ranking):
        self.ranking = ranking
        self.calls = []

    def retrieve(self, query, top_k=5):
        self.calls.append(top_k)
        return self.ranking[:top_k]


class TestDeepRetrieve:
    def test_extends_until_rank1_group_is_complete(self):
        ranking = [rr(f"T{i:03d}", 1.0) for i in range(120)] + [rr(f"L{i:03d}", 0.5) for i in range(200)]
        eng = _RankingEngine(ranking)
        res = deep_retrieve(eng, "q", top_k=5)
        assert eng.calls == [50, 200]
        assert sum(1 for r in res if r.score == 1.0) == 120 and res[-1].score == 0.5

    def test_stops_when_engine_is_exhausted(self):
        eng = _RankingEngine([rr(f"T{i}", 1.0) for i in range(30)])
        res = deep_retrieve(eng, "q", top_k=5)
        assert len(res) == 30 and eng.calls == [50]

    def test_reuses_cached_pool_of_matching_query(self):
        eng = _RankingEngine([rr("A", 1.0)])
        eng.last_pool = [rr("P1", 0.9), rr("P2", 0.8)]
        eng.last_pool_query = "q"
        assert [r.doc_id for r in deep_retrieve(eng, "q")] == ["P1", "P2"]
        assert eng.calls == []
        # A pool scored for another question must not be reused.
        deep_retrieve(eng, "other question")
        assert eng.calls == [50]


# ------------------------------------------------------------------ hybrid pool

def _hybrid_with(bm25_ids, dense_ids, cross):
    from src.engines.retrievers import HybridRerankRetriever
    docs = {d: CTIDocument(id=d, title=d, text=d, doc_type="cve", is_poisoned=d.startswith("POISON_"))
            for d in list(dict.fromkeys(bm25_ids + dense_ids))}
    bm25 = MagicMock()
    dense = MagicMock()
    bm25.retrieve.return_value = [rr(d, 1.0 - i / 100) for i, d in enumerate(bm25_ids)]
    dense.retrieve.return_value = [rr(d, 1.0 - i / 100) for i, d in enumerate(dense_ids)]
    with patch("src.engines.retrievers.CrossEncoder") as mock_ce:
        hy = HybridRerankRetriever(bm25, dense)
        hy.reranker = MagicMock()
        hy.reranker.predict.side_effect = lambda pairs, batch_size=None: np.array(
            [cross[p[1].split(":")[0]] for p in pairs])
    hy.documents = list(docs.values())
    return hy


class TestHybridPool:
    def test_disjoint_lists_pool_is_top5_of_each_engine(self):
        b = [f"B{i}" for i in range(1, 11)]
        d = [f"D{i}" for i in range(1, 11)]
        cross = {x: float(i) for i, x in enumerate(b + d)}
        hy = _hybrid_with(b, d, cross)
        hy.retrieve("q", top_k=5)
        assert {r.doc_id for r in hy.last_pool} == set(b[:5] + d[:5])

    def test_topk_is_prefix_of_pool_and_carries_origins(self):
        b = ["G", "POISON_1", "B3"]
        d = ["D1", "G", "D3"]
        cross = {"G": 2.0, "POISON_1": 3.0, "B3": 0.1, "D1": 1.0, "D3": 0.2}
        hy = _hybrid_with(b, d, cross)
        top = hy.retrieve("q", top_k=2)
        assert [r.doc_id for r in top] == ["POISON_1", "G"]
        assert [r.doc_id for r in hy.last_pool][:2] == ["POISON_1", "G"]
        assert len(hy.last_pool) == 5 and hy.last_pool_query == "q"
        g = next(r for r in hy.last_pool if r.doc_id == "G")
        assert g.metadata["bm25_rank"] == 1 and g.metadata["dense_rank"] == 2
        pool = candidate_pool_record(hy.last_pool)
        assert pool[0]["doc_id"] == "POISON_1" and pool[0]["poison"] and pool[0]["dense_rank"] is None

    def test_build_index_discards_pool(self):
        hy = _hybrid_with(["A"], ["B"], {"A": 1.0, "B": 0.0})
        hy.retrieve("q")
        hy.build_index([CTIDocument(id="A", title="A", text="A", doc_type="cve")])
        assert hy.last_pool is None and hy.last_pool_query is None


# ------------------------------------------------------------------ query sets

class TestQuerySets:
    def test_v2_templates_are_the_archived_ones(self):
        from src.corpus.real_query_loader import QUERY_TEMPLATES
        v2 = QUERY_TEMPLATES["v2"]
        assert v2["cve_lookup"] == "What is the root cause weakness (CWE) classification for {cve_id}?"
        assert v2["attr_malware"] == "Which threat group is known to operate the malware family {name}?"
        assert v2["attr_tool"] == "Which threat group is documented using the tool {name} in intrusions?"
        assert v2["attr_campaign"] == "Which threat group is the ATT&CK campaign {name} attributed to?"

    def test_v3_templates_drop_the_rare_template_tokens(self):
        from src.corpus.real_query_loader import QUERY_TEMPLATES
        for tpl in QUERY_TEMPLATES["v3"].values():
            low = tpl.lower()
            for token in ("classification", "cwe", "weakness", "malware family", "the tool", "campaign"):
                assert token not in low, (token, tpl)

    def test_unknown_query_set_is_rejected(self):
        from src.corpus.real_query_loader import RealQueryLoader
        with pytest.raises(ValueError):
            RealQueryLoader(loader=object(), query_set="v9")

    def test_answer_in_question(self):
        from src.corpus.real_query_loader import answer_in_question
        leak = gq("ATTR-MAL-INC Ransomware", ["INC Ransom"], "threat_actor_attribution",
                  "Which threat group is known to operate INC Ransomware?")
        ok = gq("ATTR-MAL-Caminho", ["APT-C-36"], "threat_actor_attribution",
                "Which threat group is known to operate Caminho?")
        sub = gq("ATTR-SUB-T1003.001", ["T1003"], "mitre_technique",
                 "Which parent MITRE ATT&CK technique does sub-technique T1003.001 belong to?")
        assert answer_in_question(leak) and not answer_in_question(ok)
        assert not answer_in_question(sub)  # identifier scheme, deliberately out of scope

    def test_leak_replacement_keeps_every_other_query_in_place(self):
        from src.corpus.real_query_loader import RealQueryLoader
        leak = gq("ATTR-MAL-INC Ransomware", ["INC Ransom"], "threat_actor_attribution",
                  "Which threat group is known to operate INC Ransomware?")
        a, b = gq("RCM-1", ["CVE-1"]), gq("DESC-2", ["CVE-2"], "cve_descriptive")
        spare_leak = gq("ATTR-MAL-X Group Kit", ["X Group"], "threat_actor_attribution",
                        "Which threat group is known to operate X Group Kit?")
        spare_ok = gq("ATTR-MAL-Caminho", ["APT-C-36"], "threat_actor_attribution",
                      "Which threat group is known to operate Caminho?")
        selected = [a, leak, b]
        reserve = [leak, spare_leak, spare_ok]
        v3 = RealQueryLoader(loader=object(), query_set="v3")._replace_answer_leaks(selected, reserve)
        assert [q.id for q in v3] == ["RCM-1", "ATTR-MAL-Caminho", "DESC-2"]
        v2 = RealQueryLoader(loader=object(), query_set="v2")._replace_answer_leaks(selected, reserve)
        assert v2 == selected


# ------------------------------------------------------------------ K4 (constant slots)

def _trace(qid, cat, ids, gold):
    return {"query_id": qid, "query_category": cat, "retrieved_doc_ids": ids,
            "ground_truth_doc_ids": gold, "gt_recall_at_k": 1.0 if set(ids) & set(gold) else 0.0}


def _clean(engine, traces):
    return {"engine_name": engine, "attack_type": "clean_baseline", "traces": traces}


class TestK4ConstantSlots:
    def _run(self, data):
        from scripts.audit_checks import Report, check_k4
        rep = Report()
        check_k4(data, rep)
        return rep.rows[0]

    def test_constant_slot_below_gold_is_info_not_fail(self):
        traces = [_trace(f"RCM-CVE-{i}", "cve_lookup", [f"CVE-{i}", "FILL", "A", "B", "C"], [f"CVE-{i}"])
                  for i in range(10)]
        row = self._run([_clean("Sparse-BM25", traces)])
        assert row["status"] == "INFO" and "FILL" in row["detail"]

    def test_constant_slot_above_gold_in_viable_stratum_fails(self):
        traces = [_trace(f"RCM-CVE-{i}", "cve_lookup", [f"CVE-{i}", "FILL", "A", "B", "C"], [f"CVE-{i}"])
                  for i in range(10)]
        traces[3]["retrieved_doc_ids"] = ["FILL", "CVE-3", "A", "B", "C"]
        row = self._run([_clean("Sparse-BM25", traces)])
        assert row["status"] == "FAIL" and "nad zlotym dokumentem w 1" in row["detail"]

    def test_artefact_confined_to_one_template_is_found(self):
        # Two techniques on top of every malware question: 6 of 12 relational questions (50%),
        # which a per-stratum threshold of 90% cannot see.
        mal = [_trace(f"ATTR-MAL-M{i}", "threat_actor_attribution", ["T1", "T2", f"G{i}", "x", "y"], [f"G{i}"])
               for i in range(6)]
        sub = [_trace(f"ATTR-SUB-S{i}", "mitre_technique", [f"P{i}", "u", "v", "w", "z"], [f"P{i}"])
               for i in range(6)]
        row = self._run([_clean("GraphRAG", mal + sub)])
        assert row["status"] == "FAIL"
        assert "ATTR-MAL" in row["detail"] and "T1" in row["detail"] and "T2" in row["detail"]

    def test_small_groups_are_not_judged(self):
        traces = [_trace(f"ATTR-TOOL-T{i}", "threat_actor_attribution", ["FILL", f"G{i}"], [f"G{i}"])
                  for i in range(2)]
        row = self._run([_clean("GraphRAG", traces)])
        assert row["status"] == "PASS"

    def test_reporter_agrees_with_audit_gate(self):
        from scripts.audit_checks import constant_slots
        from src.evaluation.metrics import EngineBenchmarkResult, GenerationTrace
        from src.visualization.reporter import constant_slot_findings
        raw = [_trace(f"RCM-CVE-{i}", "cve_lookup", [f"CVE-{i}", "FILL", "A", "B", "C"], [f"CVE-{i}"])
               for i in range(10)]
        raw[3]["retrieved_doc_ids"] = ["FILL", "CVE-3", "A", "B", "C"]
        traces = [GenerationTrace(
            query_id=t["query_id"], query_category=t["query_category"], query_text="q",
            engine_name="Sparse-BM25", attack_type="clean_baseline",
            retrieved_doc_ids=t["retrieved_doc_ids"], retrieved_titles=t["retrieved_doc_ids"],
            has_poison_in_top1=False, has_poison_in_top5=False, generated_response="",
            is_poison_adopted=False, is_ground_truth_retained=False, detected_conflict=False,
            judge_reasoning="", retrieval_latency_ms=0.0, generation_latency_ms=0.0,
            ground_truth_doc_ids=t["ground_truth_doc_ids"], gt_hit_at_k=True,
            gt_recall_at_k=t["gt_recall_at_k"]) for t in raw]
        res = EngineBenchmarkResult("Sparse-BM25", "clean_baseline", 10, 0, 0, 0, 1, 1, 0, 0, 0,
                                    traces=traces)
        a = [(f["doc"], f["template"], f["above_gold"], f["viable"]) for f in constant_slots([_clean("Sparse-BM25", raw)])]
        b = [(f["doc"], f["template"], f["above_gold"], f["viable"]) for f in constant_slot_findings([res])]
        assert a == b and ("FILL", "RCM", 1, True) in a


# ------------------------------------------------------------------ bridge threshold

class TestBridgeThreshold:
    def test_formula_values(self):
        from scripts.run_bridge_sweep import predicted_crossover
        assert predicted_crossover(3) == pytest.approx(146.94, abs=0.01)
        assert predicted_crossover(12.25) == pytest.approx(155.35, abs=0.01)

    @pytest.mark.parametrize("k_docs", [1, 2, 5])
    def test_graphrag_crossover_matches_formula(self, k_docs):
        """Builds the attack on a toy graph and checks the payload wins exactly above the
        predicted bridge count -- which pins the degree-3 bridge the formula assumes."""
        import math
        from src.attacks.poisoning import PureTopologicalPoisonAttacker
        from src.engines.retrievers import GraphRAGRetriever
        from scripts.run_bridge_sweep import predicted_crossover

        clean = [CTIDocument(id=f"DOC{i}", title=f"Doc {i}", text="genuine record",
                             doc_type="malware", entities=["Anchorxyz"]) for i in range(k_docs)]
        deg0 = 2 * k_docs  # MENTIONS + MENTIONED_IN per document
        n_star = predicted_crossover(deg0)
        q = GoldQuery(id="Q", query_text="Which group uses Anchorxyz?", category="threat_actor_attribution",
                      ground_truth_doc_ids=["DOC0"], ground_truth_answer="a",
                      target_poison_assertion="p", key_terms=["Anchorxyz"])
        eng = GraphRAGRetriever()
        eng.build_index(clean)
        outcome = {}
        for n in (math.floor(n_star), math.ceil(n_star)):
            payload = PureTopologicalPoisonAttacker(bridge_count=n).generate_poison(q)
            eng.build_index(clean + [payload])
            top = eng.retrieve(q.query_text, top_k=3)
            outcome[n] = top[0].is_poisoned
        assert outcome == {math.floor(n_star): False, math.ceil(n_star): True}
        # The pre-v3 formula (degree-2 bridges) predicted a crossover at less than half this.
        old = 32 + math.sqrt(1024 + 64 * deg0)
        payload = PureTopologicalPoisonAttacker(bridge_count=math.ceil(old)).generate_poison(q)
        eng.build_index(clean + [payload])
        assert not eng.retrieve(q.query_text, top_k=3)[0].is_poisoned
