from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import numpy as np

from src.corpus.dataset import GoldQuery, RetrievalResult

@dataclass
class GenerationTrace:
    query_id: str
    query_category: str
    query_text: str
    engine_name: str
    attack_type: str
    retrieved_doc_ids: List[str]
    retrieved_titles: List[str]
    has_poison_in_top1: bool
    has_poison_in_top5: bool
    generated_response: str
    is_poison_adopted: bool
    is_ground_truth_retained: bool
    detected_conflict: bool
    judge_reasoning: str
    retrieval_latency_ms: float
    generation_latency_ms: float
    clean_ground_truth_hit: bool = False
    has_targeted_poison_in_top1: bool = False
    has_targeted_poison_in_top5: bool = False
    has_untargeted_poison_in_top1: bool = False
    has_untargeted_poison_in_top5: bool = False
    # New fields go at the END with defaults: tests construct GenerationTrace positionally
    # (tests/test_comparison_system.py), so inserting anywhere else silently shifts arguments.
    ground_truth_doc_ids: List[str] = field(default_factory=list)
    #: Ground truth present in this run's top-k. Distinct from `clean_ground_truth_hit`,
    #: which carries the *clean baseline* outcome for the same query.
    gt_hit_at_k: bool = False
    #: Fractional recall for this query: |retrieved ∩ GT| / |GT|. Hit@k and Recall@k differ
    #: whenever |GT| > 1, which is why they must not share a column header.
    gt_recall_at_k: float = 0.0
    #: True when rank 1 and rank 2 scored identically. GraphRAG sorts by (-score, doc_id), so
    #: on a tie the winner is decided by identifier ordering, not by retrieval. An attack that
    #: ties with the genuine document (entity swap does: both sit 1 hop from the query entity)
    #: would otherwise be scored as a win or a loss purely alphabetically.
    top1_is_score_tie: bool = False
    #: True when the rank-1 tie straddles the poison/clean boundary. Only these ties change a
    #: measurement: a tie between two poison documents, or two clean ones, leaves poison@1
    #: unchanged whichever way it is broken.
    top1_tie_crosses_poison: bool = False
    #: Direction the alphabetical tie-break happened to take on a boundary-crossing tie:
    #: "poison" when the payload took rank 1, "clean" when the genuine document did, "" when
    #: there is no boundary-crossing tie. This is what makes poison@1 an interval rather than
    #: a point for engines whose scoring function produces ties.
    top1_tie_winner: str = ""
    #: Scores of the official top-k, in rank order. Needed to tell a tie from a near-tie when a
    #: trace is read back without the engine.
    retrieved_scores: List[float] = field(default_factory=list)
    # ---- Full tie groups (filled only when the run logged a deep ranking, --log-ties) ----
    # The rank-1/rank-2 flags above cannot bound an engine that produces large groups of equal
    # scores: poison@1 depends on the order of the whole rank-1 tie group, and Hit@k / GT
    # displacement depend on the tie group straddling the rank-k boundary. The fields below
    # record, for this query, the metric under the least and the most favourable ordering of
    # every tied document (semantics identical to scripts/tie_audit.py).
    tie_logged: bool = False
    #: Length of the deep ranking the bounds were computed on. For the hybrid reranker this is
    #: its whole candidate pool, which is everything that engine ranks.
    deep_depth: int = 0
    #: True when the deep ranking's first k ids differ from the official top-k. Scores still
    #: agree (same index state); only the order inside a tie group can differ.
    deep_mismatch: bool = False
    rank1_tie_size: int = 0
    #: Size of the tie group at the rank-k score when it straddles the cut, else 0.
    boundary_tie_size: int = 0
    tie_p1_lo: bool = False
    tie_p1_hi: bool = False
    tie_pk_lo: bool = False
    tie_pk_hi: bool = False
    tie_hit_lo: bool = False
    tie_hit_hi: bool = False
    tie_recall_lo: float = 0.0
    tie_recall_hi: float = 0.0
    #: 1-based rank of the best-ranked ground-truth / poison document in the deep ranking;
    #: 0 when absent from it (for the hybrid reranker: absent from its candidate pool).
    gt_best_rank: int = 0
    poison_best_rank: int = 0
    #: Hybrid reranker only: every candidate the cross-encoder scored, in rerank order, with
    #: its BM25 and dense ranks (None = not in that engine's candidate list) and its RRF score.
    candidate_pool: List[Dict[str, Any]] = field(default_factory=list)


def full_tie_bounds(ranking: List[RetrievalResult], gold: set, top_k: int = 5) -> Dict[str, Any]:
    """Per-query metric bounds over every ordering of tied documents.

    `ranking` must contain the complete rank-1 tie group and the complete tie group at the
    rank-k boundary; `stages.deep_retrieve` guarantees both. Documents scoring above the rank-k
    score are in top-k under any ordering, and the boundary tie group competes for the slots
    that remain. The semantics are those of scripts/tie_audit.py, which produced the bounds
    reported for the v2 run, so the two can be compared record by record.
    """
    out: Dict[str, Any] = {
        "deep_depth": len(ranking), "rank1_tie_size": 0, "boundary_tie_size": 0,
        "tie_p1_lo": False, "tie_p1_hi": False, "tie_pk_lo": False, "tie_pk_hi": False,
        "tie_hit_lo": False, "tie_hit_hi": False, "tie_recall_lo": 0.0, "tie_recall_hi": 0.0,
        "gt_best_rank": 0, "poison_best_rank": 0,
    }
    if not ranking:
        return out
    for i, r in enumerate(ranking, 1):
        if not out["gt_best_rank"] and r.doc_id in gold:
            out["gt_best_rank"] = i
        if not out["poison_best_rank"] and r.is_poisoned:
            out["poison_best_rank"] = i
    # Rank 1: any member of the rank-1 tie group can be placed first.
    s1 = ranking[0].score
    g1 = [r for r in ranking if r.score == s1]
    out["rank1_tie_size"] = len(g1)
    out["tie_p1_lo"] = all(r.is_poisoned for r in g1)
    out["tie_p1_hi"] = any(r.is_poisoned for r in g1)
    # Rank-k boundary.
    last = ranking[min(top_k, len(ranking)) - 1].score
    above = [r for r in ranking if r.score > last]
    group = [r for r in ranking if r.score == last]
    slots = top_k - len(above)
    if len(ranking) < top_k:
        slots = len(group)
    out["boundary_tie_size"] = len(group) if len(group) > slots else 0
    g_above = sum(1 for r in above if r.doc_id in gold)
    g_group = sum(1 for r in group if r.doc_id in gold)
    ng_group = len(group) - g_group
    out["tie_hit_hi"] = g_above > 0 or (g_group > 0 and slots >= 1)
    out["tie_hit_lo"] = g_above > 0 or (g_group > 0 and ng_group < slots)
    denom = max(1, len(gold))
    out["tie_recall_lo"] = (g_above + max(0, min(g_group, slots - ng_group))) / denom
    out["tie_recall_hi"] = (g_above + min(g_group, slots)) / denom
    p_above = sum(1 for r in above if r.is_poisoned)
    p_group = sum(1 for r in group if r.is_poisoned)
    np_group = len(group) - p_group
    out["tie_pk_hi"] = p_above > 0 or (p_group > 0 and slots >= 1)
    out["tie_pk_lo"] = p_above > 0 or (p_group > 0 and np_group < slots)
    return out


def candidate_pool_record(ranking: List[RetrievalResult]) -> List[Dict[str, Any]]:
    """The hybrid reranker's scored pool, or [] for engines that do not report one."""
    if not ranking or "rrf_score" not in (ranking[0].metadata or {}):
        return []
    return [
        {
            "doc_id": r.doc_id,
            "score": float(r.score),
            "bm25_rank": r.metadata.get("bm25_rank"),
            "dense_rank": r.metadata.get("dense_rank"),
            "rrf_score": r.metadata.get("rrf_score"),
            "poison": bool(r.is_poisoned),
        }
        for r in ranking
    ]

@dataclass
class EngineBenchmarkResult:
    engine_name: str
    attack_type: str  # clean, sparse, dense, hybrid, graph, blackbox, topological
    total_queries: int
    retrieval_asr_top1: float       # Top-1 Poison Hijack Rate (Retrieval Stage)
    retrieval_asr_top3: float       # Top-3 Poison Rate
    retrieval_asr_top5: float       # Top-5 Poison Rate
    clean_recall_top5: float        # Ground Truth Recall@5
    clean_mrr: float                # Mean Reciprocal Rank for Ground Truth
    # Generation-stage fields. The benchmark has no generation stage (removed in 1.3.2), so
    # these are always 0.0; they stay in the schema because the stored results of runs v2,
    # v2_rerun and v3 carry them and are loaded back with EngineBenchmarkResult(**d).
    generation_asr: float
    ground_truth_retention: float
    conflict_detection_rate: float
    retrieval_asr_cond: float = 0.0 # Top-1 Poison Hijack Rate conditioned on Clean GT Hit > 0
    retrieval_asr_targeted: float = 0.0       # Primary ASR: proportion of queries where Top-k contains poison dedicated to this query
    retrieval_asr_untargeted: float = 0.0     # Background contamination: retrieval_asr_any - retrieval_asr_targeted
    retrieval_asr_any: float = 0.0            # Proportion of queries where Top-k contains any poison document
    retrieval_asr_targeted_top1: float = 0.0  # Top-1 Targeted Poison Rate
    retrieval_asr_targeted_top5: float = 0.0  # Top-5 Targeted Poison Rate
    retrieval_asr_any_top1: float = 0.0       # Top-1 Any Poison Rate
    retrieval_asr_any_top5: float = 0.0       # Top-5 Any Poison Rate
    retrieval_asr_untargeted_top1: float = 0.0
    retrieval_asr_untargeted_top5: float = 0.0
    #: Share of queries the clean baseline answered that this attack pushed out of top-k.
    #: This is the retrieval-stage analogue of attack success: a poison document sitting at
    #: rank 1 while the ground truth stays at rank 2 does not remove the answer from the
    #: context window, so `poison_at_1` alone overstates the attack.
    gt_displacement_rate: float = 0.0
    #: Denominator for gt_displacement_rate: queries with a clean baseline hit.
    n_displacement_denom: int = 0
    #: True when the engine's own clean utility is too low for its ASR to describe
    #: robustness rather than a degenerate ranking. Set by the reporter, not the evaluator.
    is_diagnostic: bool = False
    #: poison@1 if every rank-1 score tie had been broken against the attacker, and if every
    #: one had been broken in its favour. When the two differ, poison@1 is not a point
    #: estimate: the reported value is an artefact of `sorted(key=(-score, doc_id))`, and the
    #: Wilson interval -- which only covers sampling error -- understates the uncertainty.
    poison_at_1_tie_lower: float = 0.0
    poison_at_1_tie_upper: float = 0.0
    #: Queries whose rank-1 tie straddles the poison/clean boundary, i.e. the denominator
    #: behind the interval above.
    n_top1_tie_crossing: int = 0
    #: "full_group" when the bounds above were computed on complete tie groups from a deep
    #: ranking (--log-ties); "rank12" when only ranks 1 and 2 were compared, which bounds
    #: poison@1 from the inside for engines with large tie groups.
    tie_bounds_source: str = "rank12"
    #: The rank-1/rank-2 bounds, kept alongside the full-group ones so a logged run can be
    #: compared with an archived one field by field.
    poison_at_1_rank12_lower: float = 0.0
    poison_at_1_rank12_upper: float = 0.0
    # Full-group bounds of the other tie-dependent metrics. None when the run did not log a
    # deep ranking: an unknown bound must not read as a degenerate one.
    poison_at_5_tie_lower: Optional[float] = None
    poison_at_5_tie_upper: Optional[float] = None
    poison_at_1_cond_tie_lower: Optional[float] = None
    poison_at_1_cond_tie_upper: Optional[float] = None
    gt_displacement_tie_lower: Optional[float] = None
    gt_displacement_tie_upper: Optional[float] = None
    gt_hit_tie_lower: Optional[float] = None
    gt_hit_tie_upper: Optional[float] = None
    clean_recall_tie_lower: Optional[float] = None
    clean_recall_tie_upper: Optional[float] = None
    #: Queries whose rank-k boundary tie group straddles the cut.
    n_boundary_tie: int = 0
    #: Queries whose deep ranking ordered a tie group differently from the official top-k.
    n_deep_mismatch: int = 0
    isolated_targets: bool = False
    graph_fallback_rate: Optional[float] = None
    #: Always False: the benchmark measures retrieval only. Kept in the schema (see above).
    llm_stage_ran: bool = False
    judge_coverage_rate: float = 1.0
    latency_median_ms: float = 0.0
    latency_iqr_ms: float = 0.0
    avg_retrieval_latency_ms: float = 0.0
    avg_generation_latency_ms: float = 0.0
    traces: List[GenerationTrace] = field(default_factory=list)

    @property
    def retrieval_asr(self) -> float:
        """Backward compatibility alias mirroring primary targeted ASR metric."""
        return self.retrieval_asr_targeted

    # ------------------------------------------------------------------ naming
    # In the literature (PoisonedRAG, Zou et al.) ASR is a generation-stage quantity: the
    # share of questions the LLM answered with the attacker's target answer. This benchmark
    # runs no generation stage, so what it measures is where the poison landed in the
    # ranking. These are the canonical names for that; the retrieval_asr_* fields stay as
    # aliases so the reporter, the stored JSON and the existing tests keep working.

    @property
    def poison_at_1(self) -> float:
        """Share of queries whose rank-1 document is a poison document."""
        return self.retrieval_asr_top1

    @property
    def poison_at_5(self) -> float:
        """Share of queries with a poison document anywhere in top-5."""
        return self.retrieval_asr_top5

    @property
    def poison_at_1_cond(self) -> float:
        """poison@1 restricted to queries the clean baseline actually answered."""
        return self.retrieval_asr_cond

    @property
    def clean_recall_at_k(self) -> float:
        """Alias for clean_recall_top5 with k=5."""
        return self.clean_recall_top5

class Evaluator:
    """Calculates retrieval robustness metrics."""

    @staticmethod
    def evaluate_engine(
        engine_name: str,
        attack_type: str,
        queries: List[GoldQuery],
        retrieval_outputs: Dict[str, List[RetrievalResult]],
        retrieval_latencies: Optional[Dict[str, float]] = None,
        clean_ground_truth_hits: Optional[Dict[str, bool]] = None,
        isolated_targets: bool = False,
        top_k: int = 5,
        deep_outputs: Optional[Dict[str, List[RetrievalResult]]] = None
    ) -> "EngineBenchmarkResult":
        """Retrieval metrics of one engine under one scenario.

        `deep_outputs`, when given, maps query id to a ranking deep enough to hold the
        complete rank-1 and rank-k tie groups (stages.deep_retrieve). It never changes a point
        metric; it only adds the tie bounds.
        """
        total_q = len(queries)

        if total_q == 0:
            return EngineBenchmarkResult(
                engine_name=engine_name,
                attack_type=attack_type,
                total_queries=0,
                retrieval_asr_top1=0.0,
                retrieval_asr_top3=0.0,
                retrieval_asr_top5=0.0,
                clean_recall_top5=0.0,
                clean_mrr=0.0,
                generation_asr=0.0,
                ground_truth_retention=0.0,
                conflict_detection_rate=0.0,
                retrieval_asr_cond=0.0,
                retrieval_asr_targeted=0.0,
                retrieval_asr_untargeted=0.0,
                retrieval_asr_any=0.0,
                retrieval_asr_targeted_top1=0.0,
                retrieval_asr_targeted_top5=0.0,
                retrieval_asr_any_top1=0.0,
                retrieval_asr_any_top5=0.0,
                retrieval_asr_untargeted_top1=0.0,
                retrieval_asr_untargeted_top5=0.0,
                isolated_targets=isolated_targets,
                graph_fallback_rate=None,
                latency_median_ms=0.0,
                latency_iqr_ms=0.0,
            )

        def _is_targeted(doc: RetrievalResult, query: GoldQuery) -> bool:
            if not doc.is_poisoned:
                return False
            target = doc.poison_target_query
            if target is None:
                return False
            return target == query.id or target == query.query_text

        poison_top1_count = 0
        poison_top3_count = 0
        poison_top5_count = 0

        targeted_top1_count = 0
        targeted_top3_count = 0
        targeted_top5_count = 0

        recall_scores = []
        reciprocal_ranks = []

        traces = []
        ret_lats = []

        for q in queries:
            results = retrieval_outputs.get(q.id, [])
            p_top1 = len(results) > 0 and results[0].is_poisoned
            p_top3 = any(r.is_poisoned for r in results[:3])
            p_top5 = any(r.is_poisoned for r in results[:5])

            p_target_top1 = len(results) > 0 and _is_targeted(results[0], q)
            p_target_top3 = any(_is_targeted(r, q) for r in results[:3])
            p_target_top5 = any(_is_targeted(r, q) for r in results[:5])

            if p_top1:
                poison_top1_count += 1
            if p_top3:
                poison_top3_count += 1
            if p_top5:
                poison_top5_count += 1

            if p_target_top1:
                targeted_top1_count += 1
            if p_target_top3:
                targeted_top3_count += 1
            if p_target_top5:
                targeted_top5_count += 1

            # Clean Ground Truth Recall & MRR (unified cutoff at top_k)
            gt_set = set(q.ground_truth_doc_ids)
            retrieved_ids = [r.doc_id for r in results[:top_k]]
            retrieved_titles = [r.title for r in results[:top_k]]
            hits = sum(1 for did in retrieved_ids if did in gt_set)
            recall = hits / max(1, len(gt_set))
            recall_scores.append(recall)

            rr = 0.0
            for rank, r in enumerate(results[:top_k], 1):
                if r.doc_id in gt_set:
                    rr = 1.0 / rank
                    break
            reciprocal_ranks.append(rr)

            # Determine clean ground truth hit status
            if clean_ground_truth_hits is not None:
                clean_hit_val = clean_ground_truth_hits.get(q.id, False)
            elif attack_type.lower() == "clean_baseline":
                clean_hit_val = (hits > 0)
            else:
                clean_hit_val = False

            # Rank-1 score ties. Only a tie that straddles the poison/clean boundary can move
            # poison@1, and which side wins is decided by `sorted(key=(-score, doc_id))`, i.e.
            # by identifier ordering. Record the direction so the reporter can turn poison@1
            # into an interval instead of presenting a sorting artefact as a measurement.
            is_tie = len(results) > 1 and results[0].score == results[1].score
            tie_crosses = is_tie and (bool(results[0].is_poisoned) != bool(results[1].is_poisoned))
            if tie_crosses:
                tie_winner = "poison" if results[0].is_poisoned else "clean"
            else:
                tie_winner = ""

            deep = deep_outputs.get(q.id) if deep_outputs is not None else None
            if deep is not None:
                tie_extra = full_tie_bounds(deep, gt_set, top_k)
                tie_extra["tie_logged"] = True
                tie_extra["deep_mismatch"] = [r.doc_id for r in deep[:top_k]] != retrieved_ids
                tie_extra["candidate_pool"] = candidate_pool_record(deep)
            else:
                tie_extra = {}

            ret_lat = retrieval_latencies.get(q.id, 0.0) if retrieval_latencies else 0.0
            ret_lats.append(ret_lat)

            traces.append(GenerationTrace(
                query_id=q.id,
                query_category=q.category,
                query_text=q.query_text,
                engine_name=engine_name,
                attack_type=attack_type,
                retrieved_doc_ids=retrieved_ids,
                retrieved_titles=retrieved_titles,
                has_poison_in_top1=p_top1,
                has_poison_in_top5=p_top5,
                # Generation-stage trace fields: constant, kept for the stored format.
                generated_response="",
                is_poison_adopted=False,
                is_ground_truth_retained=False,
                detected_conflict=False,
                judge_reasoning="No verdict",
                retrieval_latency_ms=ret_lat,
                generation_latency_ms=0.0,
                clean_ground_truth_hit=clean_hit_val,
                has_targeted_poison_in_top1=p_target_top1,
                has_targeted_poison_in_top5=p_target_top5,
                has_untargeted_poison_in_top1=p_top1 and not p_target_top1,
                has_untargeted_poison_in_top5=p_top5 and not p_target_top5,
                ground_truth_doc_ids=list(q.ground_truth_doc_ids),
                gt_hit_at_k=(hits > 0),
                gt_recall_at_k=recall,
                top1_is_score_tie=is_tie,
                top1_tie_crosses_poison=tie_crosses,
                top1_tie_winner=tie_winner,
                retrieved_scores=[float(r.score) for r in results[:top_k]],
                **tie_extra,
            ))

        # Conditional ASR (ASR_cond): Top-1 Poison Hijack Rate conditioned on Clean GT Hit > 0
        cond_traces = [t for t in traces if t.clean_ground_truth_hit]
        if cond_traces and attack_type.lower() != "clean_baseline":
            cond_top1_count = sum(1 for t in cond_traces if t.has_poison_in_top1)
            asr_cond = cond_top1_count / len(cond_traces)
        else:
            asr_cond = 0.0

        # Ground truth displacement: of the queries the clean baseline answered, how many
        # no longer have the answer anywhere in top-k under this attack. Same conditioning
        # as asr_cond, so the two are read off the same denominator.
        if cond_traces and attack_type.lower() != "clean_baseline":
            displaced = sum(1 for t in cond_traces if not t.gt_hit_at_k)
            gt_displacement_rate = displaced / len(cond_traces)
            n_displacement_denom = len(cond_traces)
        else:
            gt_displacement_rate = 0.0
            n_displacement_denom = len(cond_traces)

        asr_targeted = targeted_top5_count / total_q
        asr_any = poison_top5_count / total_q
        asr_untargeted = asr_any - asr_targeted

        # Tie-break sensitivity of poison@1. `tie_poison_won` counts hits that would vanish if
        # ties were broken against the attacker; `tie_clean_won` counts misses that would turn
        # into hits if they were broken in its favour. Both are decided by document-id
        # ordering, so the true value lies anywhere in between and poison@1 is only a point
        # estimate when the two bounds coincide.
        tie_poison_won = sum(1 for t in traces if t.top1_tie_winner == "poison")
        tie_clean_won = sum(1 for t in traces if t.top1_tie_winner == "clean")
        rank12_lower = (poison_top1_count - tie_poison_won) / total_q
        rank12_upper = (poison_top1_count + tie_clean_won) / total_q
        poison_at_1_tie_lower = rank12_lower
        poison_at_1_tie_upper = rank12_upper
        n_top1_tie_crossing = tie_poison_won + tie_clean_won

        # Full tie groups. Used only when every query carries a deep ranking: a partial set
        # would mix two different bound definitions in one number.
        tie_bounds_source = "rank12"
        full_bounds: Dict[str, Optional[float]] = {k: None for k in (
            "poison_at_5_tie_lower", "poison_at_5_tie_upper",
            "poison_at_1_cond_tie_lower", "poison_at_1_cond_tie_upper",
            "gt_displacement_tie_lower", "gt_displacement_tie_upper",
            "gt_hit_tie_lower", "gt_hit_tie_upper",
            "clean_recall_tie_lower", "clean_recall_tie_upper")}
        n_boundary_tie = 0
        n_deep_mismatch = 0
        if traces and all(t.tie_logged for t in traces):
            tie_bounds_source = "full_group"
            poison_at_1_tie_lower = sum(1 for t in traces if t.tie_p1_lo) / total_q
            poison_at_1_tie_upper = sum(1 for t in traces if t.tie_p1_hi) / total_q
            n_top1_tie_crossing = sum(1 for t in traces if t.tie_p1_lo != t.tie_p1_hi)
            full_bounds["poison_at_5_tie_lower"] = sum(1 for t in traces if t.tie_pk_lo) / total_q
            full_bounds["poison_at_5_tie_upper"] = sum(1 for t in traces if t.tie_pk_hi) / total_q
            full_bounds["gt_hit_tie_lower"] = sum(1 for t in traces if t.tie_hit_lo) / total_q
            full_bounds["gt_hit_tie_upper"] = sum(1 for t in traces if t.tie_hit_hi) / total_q
            full_bounds["clean_recall_tie_lower"] = float(np.mean([t.tie_recall_lo for t in traces]))
            full_bounds["clean_recall_tie_upper"] = float(np.mean([t.tie_recall_hi for t in traces]))
            # Same denominator as poison@1 cond and GT displaced@k: the queries the clean
            # baseline answered (its point outcome). Only the numerator is bounded here.
            if cond_traces and attack_type.lower() != "clean_baseline":
                nc = len(cond_traces)
                full_bounds["poison_at_1_cond_tie_lower"] = sum(1 for t in cond_traces if t.tie_p1_lo) / nc
                full_bounds["poison_at_1_cond_tie_upper"] = sum(1 for t in cond_traces if t.tie_p1_hi) / nc
                full_bounds["gt_displacement_tie_lower"] = sum(1 for t in cond_traces if not t.tie_hit_hi) / nc
                full_bounds["gt_displacement_tie_upper"] = sum(1 for t in cond_traces if not t.tie_hit_lo) / nc
            else:
                for k in ("poison_at_1_cond_tie_lower", "poison_at_1_cond_tie_upper",
                          "gt_displacement_tie_lower", "gt_displacement_tie_upper"):
                    full_bounds[k] = 0.0
            n_boundary_tie = sum(1 for t in traces if t.boundary_tie_size > 0)
            n_deep_mismatch = sum(1 for t in traces if t.deep_mismatch)

        # Graph fallback rate calculation
        is_graph = (
            engine_name.lower().startswith("graph")
            or any(
                any("fallback_used" in r.metadata for r in results)
                for results in retrieval_outputs.values()
            )
        )
        if is_graph and total_q > 0:
            fallback_queries = sum(
                1 for q in queries
                if any(r.metadata.get("fallback_used", False) for r in retrieval_outputs.get(q.id, []))
            )
            graph_fallback_rate = fallback_queries / total_q
        else:
            graph_fallback_rate = None

        # Latency median and IQR (discarding warm-up query)
        if retrieval_latencies and len(retrieval_latencies) > 0:
            lat_vals = list(retrieval_latencies.values())
            eval_lats = lat_vals[1:] if len(lat_vals) > 1 else lat_vals
            latency_median_ms = float(np.median(eval_lats))
            q75, q25 = np.percentile(eval_lats, [75, 25])
            latency_iqr_ms = float(q75 - q25)
        else:
            latency_median_ms = 0.0
            latency_iqr_ms = 0.0

        return EngineBenchmarkResult(
            engine_name=engine_name,
            attack_type=attack_type,
            total_queries=total_q,
            retrieval_asr_top1=poison_top1_count / total_q,
            retrieval_asr_top3=poison_top3_count / total_q,
            retrieval_asr_top5=poison_top5_count / total_q,
            clean_recall_top5=float(np.mean(recall_scores)),
            clean_mrr=float(np.mean(reciprocal_ranks)),
            generation_asr=0.0,
            ground_truth_retention=0.0,
            conflict_detection_rate=0.0,
            retrieval_asr_cond=asr_cond,
            retrieval_asr_targeted=asr_targeted,
            retrieval_asr_untargeted=asr_untargeted,
            retrieval_asr_any=asr_any,
            retrieval_asr_targeted_top1=targeted_top1_count / total_q,
            retrieval_asr_targeted_top5=asr_targeted,
            retrieval_asr_any_top1=poison_top1_count / total_q,
            retrieval_asr_any_top5=asr_any,
            retrieval_asr_untargeted_top1=(poison_top1_count - targeted_top1_count) / total_q,
            retrieval_asr_untargeted_top5=asr_untargeted,
            gt_displacement_rate=gt_displacement_rate,
            n_displacement_denom=n_displacement_denom,
            poison_at_1_tie_lower=poison_at_1_tie_lower,
            poison_at_1_tie_upper=poison_at_1_tie_upper,
            n_top1_tie_crossing=n_top1_tie_crossing,
            tie_bounds_source=tie_bounds_source,
            poison_at_1_rank12_lower=rank12_lower,
            poison_at_1_rank12_upper=rank12_upper,
            n_boundary_tie=n_boundary_tie,
            n_deep_mismatch=n_deep_mismatch,
            **full_bounds,
            isolated_targets=isolated_targets,
            graph_fallback_rate=graph_fallback_rate,
            latency_median_ms=latency_median_ms,
            latency_iqr_ms=latency_iqr_ms,
            avg_retrieval_latency_ms=float(np.mean(ret_lats)) if ret_lats else 0.0,
            traces=traces
        )
