import json
import math
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from tabulate import tabulate
from rich.console import Console
from rich.table import Table
from src.evaluation.metrics import EngineBenchmarkResult, GenerationTrace
from src.config import config

console = Console()

def wilson_interval(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """Calculate Wilson score confidence interval (95% default)."""
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + (z**2) / total
    center = (p + (z**2) / (2 * total)) / denom
    margin = (z * math.sqrt((p * (1 - p) / total) + (z**2) / (4 * (total**2)))) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))

def format_p_value(p: float) -> str:
    """Formats p-values avoiding false zero '0.0000' for very small values."""
    if p < 0.0001:
        return "< 0.0001"
    return f"{p:.4f}"

def mcnemar_test_detailed(outcomes_a: List[bool], outcomes_b: List[bool]) -> Dict[str, Any]:
    """McNemar's test for paired binary outcomes returning detailed test statistics, variant, and discordant counts."""
    b = sum(1 for a, o in zip(outcomes_a, outcomes_b) if a and not o)  # A=success/poisoned, B=not
    c = sum(1 for a, o in zip(outcomes_a, outcomes_b) if not a and o)  # A=not, B=success/poisoned
    n = b + c
    if n == 0:
        return {
            "stat": 0.0,
            "stat_label": "0.00",
            "p_val": 1.0,
            "is_sig": False,
            "variant": "Brak niezgodności (n=0)",
            "b": 0,
            "c": 0,
            "n": 0
        }

    if n < 25:
        # Exact two-tailed binomial test under H0: p = 0.5
        k = min(b, c)
        p_val = 2.0 * sum(math.comb(n, i) * (0.5 ** n) for i in range(k + 1))
        p_val = min(1.0, p_val)
        stat = float(abs(b - c))
        return {
            "stat": stat,
            "stat_label": f"|b-c| = {int(stat)}",
            "p_val": p_val,
            "is_sig": p_val < 0.05,
            "variant": "Exact Binomial",
            "b": b,
            "c": c,
            "n": n
        }

    # McNemar with continuity correction for large samples
    chi2 = (abs(b - c) - 1) ** 2 / n
    from math import erfc, sqrt
    p_value = erfc(sqrt(chi2 / 2))
    return {
        "stat": chi2,
        "stat_label": f"χ² = {chi2:.2f}",
        "p_val": p_value,
        "is_sig": p_value < 0.05,
        "variant": "Asymptotic Chi² (CC)",
        "b": b,
        "c": c,
        "n": n
    }

def mcnemar_test(outcomes_a: List[bool], outcomes_b: List[bool]) -> Tuple[float, float, bool]:
    """McNemar's test for paired binary outcomes. Returns (stat, p_value, is_significant_at_005)."""
    res = mcnemar_test_detailed(outcomes_a, outcomes_b)
    return res["stat"], res["p_val"], res["is_sig"]

MIN_UTILITY_THRESHOLD = 0.50

#: Query categories grouped into reporting strata. Aggregating across these hides that they
#: are different tasks: exact-match id lookup, description matching, and graph traversal.
STRATUM_BY_CATEGORY = {
    "cve_lookup": "cve_exact",
    "cve_descriptive": "cve_descriptive",
}
STRATUM_DEFAULT = "attack_relational"

STRATUM_LABELS = {
    "cve_exact": "CVE Exact-Match (ID w pytaniu)",
    "cve_descriptive": "CVE Descriptive (bez ID)",
    "attack_relational": "ATT&CK Relational (graf)",
}
STRATUM_ORDER = ["cve_exact", "cve_descriptive", "attack_relational"]

#: Honest one-line characterisation of what each stratum actually tests. These matter: the
#: exact-match stratum is a key lookup, not a retrieval task, and the descriptive stratum is
#: near-duplicate matching, not root-cause reasoning. Naming them as harder tasks than they
#: are is how a benchmark ends up overstating what it measured.
STRATUM_NOTES = {
    "cve_exact": (
        "*Identyfikator CVE występuje dosłownie w treści pytania, a dokumentem docelowym jest "
        "rekord o tym identyfikatorze. To zadanie wyszukiwania po kluczu, nie wyszukiwania "
        "semantycznego — sprzyja metodom leksykalnym i linkowaniu encji.*"
    ),
    "cve_descriptive": (
        "*Pytanie zawiera opis podatności z wyciętym identyfikatorem. Opis jest podciągiem "
        "dokumentu docelowego, więc jest to dopasowanie near-duplicate — zadanie uczciwsze niż "
        "lookup po ID, ale nie jest to klasyfikacja przyczyny źródłowej z CTIBench.*"
    ),
    "attack_relational": (
        "*Nazwa poszukiwanej encji nie występuje w pytaniu — wymagane jest przejście po grafie "
        "powiązań. Uwaga: zbiór odpowiedzi wyprowadzono z tych samych krawędzi STIX, po których "
        "chodzi GraphRAG, więc przewaga wyszukiwania grafowego jest tu częściowo wbudowana "
        "w konstrukcję zadania.*"
    ),
}


def stratum_of(category: str) -> str:
    return STRATUM_BY_CATEGORY.get(category or "", STRATUM_DEFAULT)


def attack_base(attack_type: str) -> str:
    """Strips the budget suffix: 'blackbox_category_b3' -> 'blackbox_category'.

    Prefix matching is not safe here because 'blackbox' is a prefix of
    'blackbox_category'; comparing bases keeps the two vectors distinct.
    """
    return re.sub(r"_b\d+$", "", (attack_type or "").lower())

#: Every attacker in src/attacks/poisoning.py mints its payload id with this prefix, which is
#: what lets a trace holding only document ids recover whether a rank-1 tie straddles the
#: poison/clean boundary.
POISON_ID_PREFIX = "POISON_"

#: The query-echo arm appends the victim's question verbatim to the payload. It is declared an
#: upper-bound stress test, so it must not be averaged into a headline robustness number
#: alongside the reference arm -- it is reported as its own column instead.
ECHO_ATTACK_BASES = {"dense_echo"}


def trace_tie_winner(trace) -> str:
    """Which side an alphabetically-broken rank-1 tie went to: 'poison', 'clean' or ''.

    Prefers the field the evaluator records. Falls back to the document-id prefix for runs
    stored before that field existed, so an archived results file can still be re-rendered
    with the tie interval rather than silently reporting a point estimate.
    """
    winner = getattr(trace, "top1_tie_winner", "") or ""
    if winner:
        return winner
    # Older traces carry only `top1_is_score_tie`; reconstruct the direction from the ids.
    if not getattr(trace, "top1_is_score_tie", False):
        return ""
    ids = list(getattr(trace, "retrieved_doc_ids", []) or [])
    if len(ids) < 2:
        return ""
    first_poison = ids[0].startswith(POISON_ID_PREFIX)
    second_poison = ids[1].startswith(POISON_ID_PREFIX)
    if first_poison == second_poison:
        return ""
    return "poison" if first_poison else "clean"


def tie_bounds(result: EngineBenchmarkResult) -> Tuple[float, float, int]:
    """(lower, upper, n_crossing) for poison@1 under both tie-break directions."""
    stored_n = getattr(result, "n_top1_tie_crossing", 0) or 0
    if stored_n:
        return (
            getattr(result, "poison_at_1_tie_lower", result.retrieval_asr_top1),
            getattr(result, "poison_at_1_tie_upper", result.retrieval_asr_top1),
            stored_n,
        )
    n = result.total_queries or 1
    won = sum(1 for t in result.traces if trace_tie_winner(t) == "poison")
    lost = sum(1 for t in result.traces if trace_tie_winner(t) == "clean")
    hits = result.retrieval_asr_top1 * n
    return ((hits - won) / n, (hits + lost) / n, won + lost)


def compute_stratum_recall(
    results: List[EngineBenchmarkResult]
) -> Dict[Tuple[str, str], float]:
    """Per (engine, stratum) clean Recall@5, read strictly off the clean baseline."""
    out: Dict[Tuple[str, str], float] = {}
    for r in results:
        if r.attack_type.lower() != "clean_baseline":
            continue
        buckets: Dict[str, List[float]] = {}
        for t in r.traces:
            st = stratum_of(getattr(t, "query_category", ""))
            buckets.setdefault(st, []).append(getattr(t, "gt_recall_at_k", 0.0))
        for st, vals in buckets.items():
            out[(r.engine_name, st)] = sum(vals) / len(vals) if vals else 0.0
    return out


def viable_strata_for(
    stratum_recall: Dict[Tuple[str, str], float],
    engine: str,
    threshold: float = 0.50
) -> set:
    """Strata where this engine clears the utility floor.

    The floor is what disqualifies an engine's poison@1 from describing robustness: below it
    the ranking is degenerate, so a payload landing at rank 1 displaced nothing. That argument
    is about a *ranking*, not about an engine, so it applies per stratum. Applying it only at
    engine level is how GraphRAG's aggregates came to be dominated by a stratum in which its
    clean Recall@5 is 0.0%.
    """
    return {
        st for (eng, st), rec in stratum_recall.items()
        if eng == engine and rec >= threshold
    }


def restricted_poison_rates(
    result: EngineBenchmarkResult,
    viable: set
) -> Optional[Dict[str, float]]:
    """poison@1 / poison@5 / GT displacement recomputed over viable strata only.

    Returns None when the engine has no viable stratum at all, so callers drop it from the
    aggregate instead of averaging in a number computed on nothing.
    """
    ts = [t for t in result.traces if stratum_of(getattr(t, "query_category", "")) in viable]
    if not ts:
        return None
    cond = [t for t in ts if getattr(t, "clean_ground_truth_hit", False)]
    return {
        "poison_at_1": sum(1 for t in ts if getattr(t, "has_poison_in_top1", False)) / len(ts),
        "poison_at_5": sum(1 for t in ts if getattr(t, "has_poison_in_top5", False)) / len(ts),
        "displaced": (
            sum(1 for t in cond if not getattr(t, "gt_hit_at_k", False)) / len(cond)
            if cond else 0.0
        ),
        "n": float(len(ts)),
        "n_cond": float(len(cond)),
    }


def is_echo_arm(attack_type: str) -> bool:
    return attack_base(attack_type) in ECHO_ATTACK_BASES


def template_of(query_id: str) -> str:
    """Question template of a query, read off its id (RCM-..., DESC-..., ATTR-MAL-..., ...)."""
    parts = (query_id or "").split("-")
    return "-".join(parts[:2]) if parts[0] == "ATTR" else parts[0]


def constant_slot_findings(
    results: List[EngineBenchmarkResult],
    share_threshold: float = 0.90,
    min_group: int = 5
) -> List[Dict[str, Any]]:
    """Documents holding a clean top-k slot for more than `share_threshold` of the questions
    of one template group, with the number of questions where they rank above the gold one.

    Grouping by template rather than by stratum is what finds an artefact confined to one
    template (in v2, GraphRAG's two techniques on all 17 malware questions: 34% of its
    stratum). The above-gold count is what separates a harmless constant slot from a harmful
    one: when the questions of a group share every word but the identifier, the non-gold slots
    go to the documents that best match the shared words -- the same ones for every question.
    That is structural for single-document key lookup. It changes a measurement only when the
    constant document ranks above the gold one, because the attacker then needs one payload
    fewer to push the gold document out of the window.
    """
    recall = compute_stratum_recall(results)
    out: List[Dict[str, Any]] = []
    for r in results:
        if r.attack_type.lower() != "clean_baseline":
            continue
        groups: Dict[Tuple[str, str], List[Any]] = {}
        for t in r.traces:
            key = (stratum_of(getattr(t, "query_category", "")), template_of(getattr(t, "query_id", "")))
            groups.setdefault(key, []).append(t)
        for (st, tpl), ts in sorted(groups.items()):
            if len(ts) < min_group:
                continue
            counts: Dict[str, int] = {}
            for t in ts:
                for did in getattr(t, "retrieved_doc_ids", []) or []:
                    counts[did] = counts.get(did, 0) + 1
            for doc, c in sorted(counts.items(), key=lambda kv: -kv[1]):
                share = c / len(ts)
                if share <= share_threshold:
                    break
                above = 0
                for t in ts:
                    ids = list(getattr(t, "retrieved_doc_ids", []) or [])
                    gold = set(getattr(t, "ground_truth_doc_ids", []) or [])
                    if doc not in ids or doc in gold:
                        continue
                    g_ranks = [i for i, x in enumerate(ids) if x in gold]
                    if not g_ranks or ids.index(doc) < min(g_ranks):
                        above += 1
                out.append({
                    "engine": r.engine_name, "stratum": st, "template": tpl, "doc": doc,
                    "share": share, "n": len(ts), "above_gold": above,
                    "viable": recall.get((r.engine_name, st), 0.0) >= 0.50,
                })
    return out


def constant_slot_offenders(
    results: List[EngineBenchmarkResult],
    share_threshold: float = 0.90
) -> List[Tuple[str, str, str, float]]:
    """(engine, stratum, doc_id, share) where one document holds a top-k slot for nearly
    every query of a stratum.

    This is the same degeneracy that disqualifies an engine from the robustness aggregates,
    but measured per slot rather than per engine: a document that is present regardless of the
    question is not a retrieval result, and it permanently costs the context window one slot.
    """
    offenders = []
    for r in results:
        if r.attack_type.lower() != "clean_baseline":
            continue
        buckets: Dict[str, List[Any]] = {}
        for t in r.traces:
            buckets.setdefault(stratum_of(getattr(t, "query_category", "")), []).append(t)
        for st, ts in buckets.items():
            counts: Dict[str, int] = {}
            for t in ts:
                for did in getattr(t, "retrieved_doc_ids", []) or []:
                    counts[did] = counts.get(did, 0) + 1
            if not counts:
                continue
            doc, c = max(counts.items(), key=lambda kv: kv[1])
            share = c / len(ts)
            if share >= share_threshold:
                offenders.append((r.engine_name, st, doc, share))
    return offenders


def is_isolated_run(results: List[EngineBenchmarkResult], explicit_flag: Optional[bool] = None) -> bool:
    """Detects whether benchmark results were executed under isolated targets protocol."""
    if explicit_flag is not None:
        return explicit_flag
    return any(getattr(r, "isolated_targets", False) for r in results)

def compute_pareto_ranking(
    results: List[EngineBenchmarkResult],
    utility_threshold: float = MIN_UTILITY_THRESHOLD,
    stratum_recall: Optional[Dict[Tuple[str, str], float]] = None
) -> List[Dict[str, Any]]:
    """Calculates true Pareto non-dominated frontier with a baseline utility floor (Clean Recall@5 >= utility_threshold).

    Methodology:
    - Baseline Utility (is_viable) is extracted STRICTLY from the CLEAN_BASELINE scenario (no averaging across attacks).
    - Attack robustness is averaged across adversarial scenarios only, and only over the
      strata where that engine clears the utility floor. The floor exists because a payload
      reaching rank 1 in a ranking that never held the answer displaced nothing; that is a
      property of the ranking, so it has to be applied per stratum, not only per engine.
    - The query-echo arm is an upper-bound stress test and is reported as its own column
      instead of being averaged into the headline robustness number.
    - True Pareto non-dominance is identified in (Clean Recall bazowy ↑, Średni targeted poison@5 ↓).
    """
    import numpy as np
    by_engine: Dict[str, List[EngineBenchmarkResult]] = {}
    for r in results:
        by_engine.setdefault(r.engine_name, []).append(r)

    if stratum_recall is None:
        stratum_recall = compute_stratum_recall(results)

    engine_entries: List[Dict[str, Any]] = []
    for eng, eng_results in by_engine.items():
        # 1. Baseline Utility: extract STRICTLY from clean baseline scenario
        clean_r = next((r for r in eng_results if r.attack_type.lower() in ("clean_baseline", "clean")), None)
        if clean_r is not None:
            baseline_recall = clean_r.clean_recall_top5
            baseline_mrr = clean_r.clean_mrr
        elif len(eng_results) == 1:
            # Standalone single-scenario evaluation / test mock
            baseline_recall = eng_results[0].clean_recall_top5
            baseline_mrr = eng_results[0].clean_mrr
        else:
            # Multi-scenario run without clean baseline: do NOT average poisoned scenarios
            baseline_recall = 0.0
            baseline_mrr = 0.0

        def _extract_asr(r: EngineBenchmarkResult) -> float:
            if getattr(r, "retrieval_asr_targeted", None) is not None and r.retrieval_asr_targeted > 0.0:
                return r.retrieval_asr_targeted
            if getattr(r, "retrieval_asr_targeted_top1", None) is not None:
                return r.retrieval_asr_targeted_top1
            return getattr(r, "retrieval_asr_top1", 0.0)

        # 2. Attack Robustness: compute across adversarial scenarios
        attack_res = [r for r in eng_results if r.attack_type.lower() not in ("clean_baseline", "clean")]
        if attack_res:
            avg_asr = float(np.mean([_extract_asr(r) for r in attack_res]))
            avg_top1 = float(np.mean([r.retrieval_asr_top1 for r in attack_res]))
        else:
            avg_asr = float(np.mean([_extract_asr(r) for r in eng_results])) if eng_results else 0.0
            avg_top1 = float(np.mean([r.retrieval_asr_top1 for r in eng_results])) if eng_results else 0.0

        # 2a. Same robustness numbers, restricted to the strata where this engine clears the
        # utility floor and split by attack arm. Falls back to the unrestricted values when
        # the results carry no traces (unit fixtures), so callers keep working.
        eng_strata = {st for (e, st) in stratum_recall.keys() if e == eng}
        viable_sts = viable_strata_for(stratum_recall, eng, utility_threshold)
        can_restrict = bool(eng_strata) and bool(viable_sts)

        ref_p1: List[float] = []
        ref_t5: List[float] = []
        echo_p1: List[float] = []
        echo_t5: List[float] = []
        for r in attack_res:
            if can_restrict:
                rates = restricted_poison_rates(r, viable_sts)
                if rates is None:
                    continue
                p1, t5 = rates["poison_at_1"], rates["poison_at_5"]
            else:
                p1, t5 = r.retrieval_asr_top1, _extract_asr(r)
            if is_echo_arm(r.attack_type):
                echo_p1.append(p1)
                echo_t5.append(t5)
            else:
                ref_p1.append(p1)
                ref_t5.append(t5)

        avg_p1_ref = float(np.mean(ref_p1)) if ref_p1 else 0.0
        avg_t5_ref = float(np.mean(ref_t5)) if ref_t5 else 0.0
        avg_p1_echo = float(np.mean(echo_p1)) if echo_p1 else None
        avg_t5_echo = float(np.mean(echo_t5)) if echo_t5 else None

        is_viable = (baseline_recall >= utility_threshold)
        if not is_viable:
            viability = "NON_VIABLE_FOR_CVE (Domain Incompatibility)" if "dense" in eng.lower() else "NON_VIABLE"
        else:
            viability = "VIABLE"

        engine_entries.append({
            "engine": eng,
            "baseline_recall": baseline_recall,
            "avg_recall": baseline_recall,  # Clean baseline utility
            "baseline_mrr": baseline_mrr,
            # Pareto axis: reference arm, viable strata only. Falls back to the unrestricted
            # mean when the results carry no traces to restrict on.
            "avg_targeted_asr": avg_t5_ref if ref_t5 else avg_asr,
            "avg_top1_asr": avg_top1,
            "avg_poison_at_1_ref": avg_p1_ref if ref_p1 else avg_top1,
            "avg_targeted_at_5_ref": avg_t5_ref if ref_t5 else avg_asr,
            "avg_poison_at_1_echo": avg_p1_echo,
            "avg_targeted_at_5_echo": avg_t5_echo,
            "avg_top1_asr_unrestricted": avg_top1,
            "avg_targeted_asr_unrestricted": avg_asr,
            "restricted_to_strata": sorted(viable_sts) if can_restrict else [],
            "excluded_strata": sorted(eng_strata - viable_sts) if can_restrict else [],
            "is_viable": is_viable,
            "viability": viability,
            "is_pareto_optimal": False,
            "pareto_rank": 999
        })

    # True Pareto Non-dominated Frontier Identification in (Clean Recall bazowy ↑, Średni Targeted ASR ↓)
    viable_candidates = [e for e in engine_entries if e["is_viable"]]
    remaining = list(viable_candidates)
    current_front_rank = 1
    while remaining:
        front = []
        for cand in remaining:
            is_dominated = False
            for other in remaining:
                if other is cand:
                    continue
                # other dominates cand iff other.recall >= cand.recall and other.asr <= cand.asr, with at least one strict
                better_or_equal_rec = (other["avg_recall"] >= cand["avg_recall"] - 1e-9)
                better_or_equal_asr = (other["avg_targeted_asr"] <= cand["avg_targeted_asr"] + 1e-9)
                strictly_better = (
                    other["avg_recall"] > cand["avg_recall"] + 1e-9 or
                    other["avg_targeted_asr"] < cand["avg_targeted_asr"] - 1e-9
                )
                if better_or_equal_rec and better_or_equal_asr and strictly_better:
                    is_dominated = True
                    break
            if not is_dominated:
                front.append(cand)

        for cand in front:
            cand["pareto_rank"] = current_front_rank
            if current_front_rank == 1:
                cand["is_pareto_optimal"] = True
            remaining.remove(cand)
        current_front_rank += 1

    # Sort final ranking:
    # 1. Viable engines first (ordered by Pareto front rank ascending, lowest ASR, highest Recall, engine name)
    # 2. Non-viable engines last (ordered by highest Recall, lowest ASR, engine name)
    engine_entries.sort(key=lambda x: (
        0 if x["is_viable"] else 1,
        x["pareto_rank"],
        x["avg_targeted_asr"] if x["is_viable"] else -x["avg_recall"],
        -x["avg_recall"] if x["is_viable"] else x["avg_targeted_asr"],
        x["engine"]
    ))
    return engine_entries

class BenchmarkReporter:
    """Generates rich terminal tables, dynamic Markdown analysis reports, statistical intervals, and JSON trace logs."""

    @staticmethod
    def print_terminal_results(results: List[EngineBenchmarkResult]):
        total_q = results[0].total_queries if results else 0
        table_title = "🛡️ CTI RAG Poisoning Benchmark (Retrieval Robustness Evaluation)"
        table = Table(title=table_title)
        table.add_column("RAG Engine", style="cyan", justify="left")
        table.add_column("Attack Vector", style="magenta", justify="left")
        table.add_column("Queries", justify="center")
        table.add_column("Retr Top-1 ASR", justify="center")
        table.add_column("ASR_cond", justify="center")
        table.add_column("Retr Top-5 ASR", justify="center")
        table.add_column("Clean Recall@5", style="green", justify="center")

        for r in results:
            cond_traces = [t for t in r.traces if getattr(t, "clean_ground_truth_hit", False)]
            n_cond = len(cond_traces)
            if r.attack_type.lower() != "clean_baseline" and n_cond > 0:
                r_cond_str = f"[bold red]{r.retrieval_asr_cond:.1%}[/bold red]" if r.retrieval_asr_cond > 0.5 else f"{r.retrieval_asr_cond:.1%}"
                r_cond_str += f" (n={n_cond})"
            else:
                r_cond_str = "N/A"

            r_top1_str = f"[bold red]{r.retrieval_asr_top1:.1%}[/bold red]" if r.retrieval_asr_top1 > 0.5 else f"{r.retrieval_asr_top1:.1%}"
            r_top5_str = f"[bold red]{r.retrieval_asr_top5:.1%}[/bold red]" if r.retrieval_asr_top5 > 0.5 else f"{r.retrieval_asr_top5:.1%}"
            
            row_items = [
                r.engine_name,
                r.attack_type.upper(),
                str(r.total_queries),
                r_top1_str,
                r_cond_str,
                r_top5_str,
                f"{r.clean_recall_top5:.1%}",
            ]
            table.add_row(*row_items)
        console.print(table)

        # Cross-Matrix Summary Table for Terminal
        unique_engines = []
        for r in results:
            if r.engine_name not in unique_engines:
                unique_engines.append(r.engine_name)
        ordered_attack_defs = [
            ("sparse", "Sparse (Keyword)"),
            ("dense", "Dense (Semantic)"),
            ("dense_echo", "Dense +Echo (PoisonedRAG)"),
            ("hybrid", "Hybrid (Dual)"),
            ("graph", "Graph (Bridge Inject)"),
            ("entity_swap", "Graph (Entity Swap)"),
            ("blackbox_category", "BlackBox (Category)"),
            ("blackbox", "BlackBox (Topic+Entity)"),
            ("pure_topological", "Topological (Pure Graph)")
        ]
        active_attacks = [
            (att, label) for att, label in ordered_attack_defs
            if any(attack_base(r.attack_type) == att for r in results)
        ]
        if active_attacks:
            matrix_table = Table(title="🎯 Full Cross-Vulnerability Matrix (Retr Top-1 ASR for Budget=1)")
            matrix_table.add_column("RAG Engine", style="cyan", justify="left")
            matrix_table.add_column("Clean Recall@5", style="green", justify="center")
            for _, label in active_attacks:
                matrix_table.add_column(label, justify="center")

            for eng in unique_engines:
                clean_r = next((r for r in results if r.engine_name == eng and r.attack_type.lower() == "clean_baseline"), None)
                clean_str = f"{clean_r.clean_recall_top5:.1%}" if clean_r else "N/A"
                row_vals = [eng, clean_str]
                for att, _ in active_attacks:
                    att_r = next((r for r in results if r.engine_name == eng and (r.attack_type.lower() == f"{att}_b1" or r.attack_type.lower() == att)), None)
                    if att_r:
                        val = att_r.retrieval_asr_top1
                        s = f"[bold red]{val:.1%}[/bold red]" if val > 0.5 else f"{val:.1%}"
                        row_vals.append(s)
                    else:
                        row_vals.append("-")
                matrix_table.add_row(*row_vals)
            console.print(matrix_table)

    @staticmethod
    def generate_markdown_report(
        results: List[EngineBenchmarkResult],
        output_file: Path,
        corpus_type: str = "real",
        corpus_size: int | None = None,
        isolated_targets: Optional[bool] = None,
        query_echo: Optional[bool] = None,
        bridge_count: Optional[int] = None,
        run_manifest: Optional[Dict[str, Any]] = None
    ) -> str:
        isolated = is_isolated_run(results, isolated_targets)

        # A rank-1 score tie that straddles the poison/clean boundary is decided by document-id
        # ordering, not by the scoring function, so poison@1 is an interval for any engine that
        # produces such ties. The column only appears when the run actually contains them.
        tie_info = {(r.engine_name, r.attack_type): tie_bounds(r) for r in results}
        has_ties = any(n_tie > 0 for _, _, n_tie in tie_info.values())

        # Per (engine, stratum) clean utility, read off the clean baseline. Drives the
        # stratum-level utility floor used by every cross-scenario aggregate below.
        clean_stratum_recall = compute_stratum_recall(results)

        tie_header = ["poison@1 (zakres remisów)"] if has_ties else []
        headers = [
            "RAG Engine", "Threat / Attack Vector", "Queries",
            "poison@1 (95% CI)", *tie_header, "poison@1 cond (95% CI)", "poison@5",
            "GT displaced@5", "Clean Recall@5", "Clean MRR"
        ]

        rows = []
        for r in results:
            n = r.total_queries
            top1_ci = wilson_interval(int(round(r.retrieval_asr_top1 * n)), n)
            top1_str = f"{r.retrieval_asr_top1:.1%} [{top1_ci[0]:.1%}-{top1_ci[1]:.1%}]"
            
            cond_traces = [t for t in r.traces if getattr(t, "clean_ground_truth_hit", False)]
            n_cond = len(cond_traces)
            if r.attack_type.lower() != "clean_baseline" and n_cond > 0:
                k_cond = sum(1 for t in cond_traces if t.has_poison_in_top1)
                cond_ci = wilson_interval(k_cond, n_cond)
                cond_str = f"{r.retrieval_asr_cond:.1%} [{cond_ci[0]:.1%}-{cond_ci[1]:.1%}] (n={n_cond})"
            else:
                cond_str = "N/A"


            # Ground truth displacement: the share of queries the clean baseline answered
            # that this attack pushed out of the window entirely. poison@1 alone cannot say
            # whether the answer survived alongside the payload.
            if r.attack_type.lower() != "clean_baseline" and getattr(r, "n_displacement_denom", 0) > 0:
                disp_str = f"{getattr(r, 'gt_displacement_rate', 0.0):.1%} (n={r.n_displacement_denom})"
            else:
                disp_str = "N/A"

            if has_ties:
                lo_t, hi_t, n_tie = tie_info[(r.engine_name, r.attack_type)]
                tie_cell = [
                    f"{lo_t:.1%}-{hi_t:.1%} (n={n_tie})" if n_tie else "brak remisów"
                ]
            else:
                tie_cell = []

            row = [
                r.engine_name,
                r.attack_type.upper(),
                n,
                top1_str,
                *tie_cell,
                cond_str,
                f"{r.retrieval_asr_top5:.1%}",
                disp_str,
                f"{r.clean_recall_top5:.1%}",
                f"{r.clean_mrr:.2f}",
            ]
            rows.append(row)
        md_table = tabulate(rows, headers=headers, tablefmt="github")

        # Cross-Vulnerability Matrix (Engines x Attack Vectors)
        unique_engines = []
        for r in results:
            if r.engine_name not in unique_engines:
                unique_engines.append(r.engine_name)

        # An engine whose clean utility is below the floor returns a near-constant, mostly
        # irrelevant result list. Its poison@1 describes that degenerate ranking, not
        # robustness, so it is marked and kept out of cross-engine aggregates and of the
        # significance tests. Decided from measured recall, never from the engine's name.
        diagnostic_engines = set()
        for eng in unique_engines:
            clean_r = next((r for r in results if r.engine_name == eng and r.attack_type.lower() == "clean_baseline"), None)
            if clean_r is not None and clean_r.clean_recall_top5 < MIN_UTILITY_THRESHOLD:
                diagnostic_engines.add(eng)
        for r in results:
            r.is_diagnostic = r.engine_name in diagnostic_engines
        engine_label = lambda e: f"{e} (diagnostyczny)" if e in diagnostic_engines else e
        ordered_attack_defs_md = [
            ("sparse", "Sparse Keyword (poison@1)"),
            ("dense", "Dense Semantic (poison@1)"),
            ("dense_echo", "Dense +Query Echo (poison@1)"),
            ("hybrid", "Hybrid Dual (poison@1)"),
            ("graph", "Graph Bridge Inject (poison@1)"),
            ("entity_swap", "Graph Entity Swap (poison@1)"),
            ("blackbox_category", "BlackBox Category (poison@1)"),
            ("blackbox", "BlackBox Topic+Entity (poison@1)"),
            ("pure_topological", "Pure Topological (poison@1)")
        ]
        active_attacks_md = [
            (att, label) for att, label in ordered_attack_defs_md
            if any(attack_base(r.attack_type) == att for r in results)
        ]
        matrix_headers = ["RAG Engine", "Clean Recall@5"] + [label for _, label in active_attacks_md]
        matrix_rows = []
        for eng in unique_engines:
            clean_r = next((r for r in results if r.engine_name == eng and r.attack_type.lower() == "clean_baseline"), None)
            clean_str = f"{clean_r.clean_recall_top5:.1%}" if clean_r else "N/A"
            row_vals = [eng, clean_str]
            for att, _ in active_attacks_md:
                att_r = next((r for r in results if r.engine_name == eng and (r.attack_type.lower() == f"{att}_b1" or r.attack_type.lower() == att)), None)
                if att_r:
                    row_vals.append(f"{att_r.retrieval_asr_top1:.1%}")
                else:
                    row_vals.append("-")
            matrix_rows.append(row_vals)
        cross_matrix_table = tabulate(matrix_rows, headers=matrix_headers, tablefmt="github")
        
        # Attack Curves Table (ASR@1 for Budgets)
        import re
        detected_budgets = set()
        for r in results:
            m = re.search(r"_b(\d+)$", r.attack_type.lower())
            if m:
                detected_budgets.add(int(m.group(1)))
        if not detected_budgets:
            detected_budgets = {1, 3, 5}
        budgets = sorted(list(detected_budgets))

        curve_rows = []
        for eng in unique_engines:
            for att, _ in active_attacks_md:
                row = [eng, att.upper()]
                has_any = False
                for b in budgets:
                    b_r = next((r for r in results if r.engine_name == eng and (r.attack_type.lower() == f"{att}_b{b}" or (b == 1 and r.attack_type.lower() == att))), None)
                    if b_r:
                        has_any = True
                        row.append(f"{b_r.retrieval_asr_top1:.1%}")
                    else:
                        row.append("-")
                if has_any:
                    curve_rows.append(row)
        
        budget_headers = ["RAG Engine", "Attack Vector"] + [f"Budget={b} (ASR@1)" for b in budgets]
        budget_curves_table = tabulate(
            curve_rows,
            headers=budget_headers,
            tablefmt="github"
        )
        
        # Stratified breakdown, one table per stratum.
        #
        # Recall@5 and Hit@5 are reported as separate columns on purpose. They are different
        # quantities whenever a query has more than one gold document (Recall@5 is fractional,
        # Hit@5 is binary), and reporting one under the other's name made the aggregate table
        # and the stratum tables fail to reconcile.
        def _stratum_traces(res, stratum):
            return [t for t in res.traces if stratum_of(getattr(t, "query_category", "")) == stratum]

        def _mean(vals):
            return sum(vals) / len(vals) if vals else 0.0

        present_strata = []
        clean_any = next((r for r in results if r.attack_type.lower() == "clean_baseline"), None)
        if clean_any is not None:
            seen = {stratum_of(getattr(t, "query_category", "")) for t in clean_any.traces}
            present_strata = [st for st in STRATUM_ORDER if st in seen]

        # Per-engine baseline utility per stratum, used both for the split table and to
        # decide stratum viability from the data instead of hardcoding engine names.
        stratum_recall = {}
        stratum_hit = {}
        for eng in unique_engines:
            clean_r = next((r for r in results if r.engine_name == eng and r.attack_type.lower() == "clean_baseline"), None)
            for st in present_strata:
                if clean_r is None:
                    stratum_recall[(eng, st)] = None
                    stratum_hit[(eng, st)] = None
                    continue
                ts = _stratum_traces(clean_r, st)
                stratum_recall[(eng, st)] = _mean([getattr(t, "gt_recall_at_k", 0.0) for t in ts])
                stratum_hit[(eng, st)] = (
                    sum(1 for t in ts if getattr(t, "gt_hit_at_k", False)),
                    len(ts),
                )

        cat_split_rows = []
        for eng in unique_engines:
            clean_r = next((r for r in results if r.engine_name == eng and r.attack_type.lower() == "clean_baseline"), None)
            if clean_r is None:
                continue
            row = [eng, f"{clean_r.clean_recall_top5:.1%}"]
            for st in present_strata:
                rec = stratum_recall[(eng, st)]
                hits, tot = stratum_hit[(eng, st)]
                row.append(f"{rec:.1%} / {hits}/{tot}" if rec is not None else "N/A")
            cat_split_rows.append(row)

        cat_split_table = tabulate(
            cat_split_rows,
            headers=["RAG Engine", "Overall Clean Recall@5"]
                    + [f"{STRATUM_LABELS[st]} (Recall@5 / Hit@5)" for st in present_strata],
            tablefmt="github"
        )

        stratum_tables = {}
        for st in present_strata:
            rows_st = []
            for eng in unique_engines:
                rec = stratum_recall.get((eng, st))
                hits_tot = stratum_hit.get((eng, st))
                if rec is None or hits_tot is None:
                    continue
                hits, tot = hits_tot
                row = [eng, f"{rec:.1%}", f"{hits}/{tot}"]
                for att, _ in active_attacks_md:
                    att_r = next(
                        (r for r in results
                         if r.engine_name == eng
                         and (r.attack_type.lower() == f"{att}_b1" or attack_base(r.attack_type) == att)),
                        None
                    )
                    if att_r is None:
                        row.append("-")
                        continue
                    ts = _stratum_traces(att_r, st)
                    p1 = sum(1 for t in ts if getattr(t, "has_poison_in_top1", False)) / max(1, len(ts))
                    row.append(f"{p1:.1%}")
                # Ground truth displacement within this stratum, conditioned on the clean
                # baseline having answered the query at all.
                disp_cells = []
                for att, _ in active_attacks_md:
                    att_r = next(
                        (r for r in results
                         if r.engine_name == eng
                         and (r.attack_type.lower() == f"{att}_b1" or attack_base(r.attack_type) == att)),
                        None
                    )
                    if att_r is None:
                        continue
                    ts = [t for t in _stratum_traces(att_r, st) if getattr(t, "clean_ground_truth_hit", False)]
                    if ts:
                        disp_cells.append(sum(1 for t in ts if not getattr(t, "gt_hit_at_k", False)) / len(ts))
                row.append(f"{max(disp_cells):.1%}" if disp_cells else "-")
                row.append(
                    "VIABLE" if rec >= MIN_UTILITY_THRESHOLD
                    else f"NON_VIABLE (<{MIN_UTILITY_THRESHOLD:.0%} Recall@5)"
                )
                rows_st.append(row)
            stratum_headers = (
                ["RAG Engine", "Clean Recall@5", "Clean Hit@5"]
                + [label for _, label in active_attacks_md]
                + ["Max GT displaced@5", "Stratum Status"]
            )
            stratum_tables[st] = tabulate(rows_st, headers=stratum_headers, tablefmt="github")

        stratum_sizes = {
            st: sum(1 for t in clean_any.traces
                    if stratum_of(getattr(t, "query_category", "")) == st)
            for st in present_strata
        } if clean_any is not None else {}

        _sep = chr(10) + chr(10)
        stratum_sections = _sep.join(
            f"### Stratum: {STRATUM_LABELS[st]} ({stratum_sizes.get(st, 0)} zapytań)"
            + _sep + STRATUM_NOTES.get(st, "")
            + _sep + stratum_tables[st]
            for st in present_strata
        ) if present_strata else "*Brak danych stratyfikacyjnych.*"
        # Dynamic Analysis: Calculate empirical resilience metrics and Pareto ranking
        attack_results = [r for r in results if r.attack_type.lower() != "clean_baseline"]
        pareto_ranking = compute_pareto_ranking(
            results,
            utility_threshold=MIN_UTILITY_THRESHOLD,
            stratum_recall=clean_stratum_recall
        ) if results else []

        ranking_rows = []
        for rank, item in enumerate(pareto_ranking, 1):
            viability_badge = "VIABLE (Pareto Optimal)" if item.get("is_pareto_optimal", False) else ("VIABLE" if item.get("is_viable", False) else "NON_VIABLE")
            echo_p1 = item.get("avg_poison_at_1_echo")
            row = [
                f"#{rank}",
                item["engine"],
                viability_badge,
                f"{item.get('avg_recall', 0.0):.1%}",
                f"{item.get('avg_poison_at_1_ref', 0.0):.1%}",
                f"{item.get('avg_targeted_at_5_ref', 0.0):.1%}",
                f"{echo_p1:.1%}" if echo_p1 is not None else "-",
                ", ".join(
                    STRATUM_LABELS.get(st, st) for st in item.get("excluded_strata", [])
                ) or "-",
            ]
            ranking_rows.append(row)

        # Column names state the quantity that is actually computed. `poison@1` is the
        # any-poison rank-1 rate (identical to the targeted rate under the isolated protocol,
        # but they are not the same quantity and the header must not claim otherwise), and the
        # @5 column is the targeted top-5 rate that forms the Pareto axis.
        ranking_headers = [
            "Rank", "Engine", "Status Pareto (Recall >= 50%)",
            "Clean Recall@5 Bazowy (Wyższy=Lepszy)",
            "Średni poison@1, ramię referencyjne (Niższy=Lepszy)",
            "Średni targeted poison@5, ramię referencyjne (Niższy=Lepszy)",
            "poison@1, ramię echo (górne ograniczenie)",
            "Strata wyłączone (poniżej progu)"
        ]
        ranking_table = tabulate(ranking_rows, headers=ranking_headers, tablefmt="github")

        # Attack Vector Efficacy. Averaged over non-diagnostic engines and, within each
        # engine, over the strata where that engine clears the utility floor: a payload that
        # reaches rank 1 in a stratum the engine never answered is not evidence about the
        # attack, only about the ranking it landed in.
        attack_stats: Dict[str, List[float]] = {}
        attack_disp: Dict[str, List[float]] = {}
        for r in attack_results:
            if r.engine_name in diagnostic_engines:
                continue
            viable_sts = viable_strata_for(clean_stratum_recall, r.engine_name, MIN_UTILITY_THRESHOLD)
            rates = restricted_poison_rates(r, viable_sts) if viable_sts else None
            if rates is not None:
                val = rates["poison_at_1"]
                disp = rates["displaced"] if rates["n_cond"] else None
            else:
                continue
            attack_stats.setdefault(r.attack_type, []).append(val)
            if disp is not None:
                attack_disp.setdefault(r.attack_type, []).append(disp)

        attack_rankings = []
        for att, asrs in attack_stats.items():
            disp_vals = attack_disp.get(att, [])
            attack_rankings.append((
                att,
                sum(asrs) / len(asrs),
                (sum(disp_vals) / len(disp_vals)) if disp_vals else None,
                len(asrs),
            ))
        # Ordered by displacement, because that is the quantity that says an attack removed the
        # answer rather than merely outranking it -- but ONLY across budgets below the window
        # size. At B >= k the payloads alone can fill the window, so displacement there is
        # arithmetic, not attack efficacy: ordering the table by it would put the saturated
        # rows on top under a heading that reads as "most effective attack". Saturated rows are
        # kept for completeness, marked, and sorted to the bottom.
        def _is_saturating(att_name: str) -> bool:
            m = re.search(r"_b(\d+)$", att_name.lower())
            return bool(m) and int(m.group(1)) >= config.TOP_K

        attack_rankings.sort(
            key=lambda x: (0 if _is_saturating(x[0]) else 1,
                           x[2] if x[2] is not None else -1.0,
                           x[1]),
            reverse=True
        )

        attack_headers = [
            "Attack Vector",
            "Avg GT displaced@5 (strata użyteczne)",
            "Avg poison@1 (strata użyteczne)",
            "Silniki (n)",
            "Reżim",
        ]
        attack_rows = [
            [
                att.upper(),
                f"{d:.1%}" if d is not None else "-",
                f"{asr:.1%}",
                n,
                f"B>=k: arytmetyka okna" if _is_saturating(att) else "sub-saturacja",
            ]
            for att, asr, d, n in attack_rankings
        ]
        attack_table = tabulate(attack_rows, headers=attack_headers, tablefmt="github")

        # McNemar's Test Pairwise Comparisons.
        #
        # Budget replicates of the same vector routinely produce byte-identical per-query
        # outcome vectors (a flat budget curve is exactly that). Emitting one row per budget
        # would count a single finding four times and inflate the family size that Holm
        # corrects over, so identical replicates are collapsed into one row that names the
        # budgets it covers.
        raw_tests = []
        test_index: Dict[Any, Dict[str, Any]] = {}
        seen_test_pairs = set()

        def _budget_of(att_name: str) -> Optional[int]:
            m = re.search(r"_b(\d+)$", att_name.lower())
            return int(m.group(1)) if m else None

        def _record_test(att_name, eng_a, eng_b, metric_name, outcomes_a, outcomes_b):
            key = (
                attack_base(att_name),
                metric_name,
                eng_a,
                eng_b,
                tuple(bool(x) for x in outcomes_a),
                tuple(bool(x) for x in outcomes_b),
            )
            budget = _budget_of(att_name)
            if key in test_index:
                if budget is not None:
                    test_index[key]["budgets"].add(budget)
                return
            res = mcnemar_test_detailed(outcomes_a, outcomes_b)
            entry = {
                "condition": f"{attack_base(att_name).upper()} ({metric_name})",
                "eng1": eng_a,
                "eng2": eng_b,
                "discordant": f"({res['b']}, {res['c']})",
                "variant": res["variant"],
                "stat_label": res["stat_label"],
                "stat": res["stat"],
                "p_val": res["p_val"],
                "budgets": {budget} if budget is not None else set(),
            }
            test_index[key] = entry
            raw_tests.append(entry)

        attacks_map = {}
        for r in results:
            att = r.attack_type.lower()
            if att not in attacks_map:
                attacks_map[att] = []
            attacks_map[att].append(r)

        for att, eng_results in attacks_map.items():
            if len(eng_results) > 1:
                unique_eng_results = []
                seen_engs = set()
                for r in eng_results:
                    if r.engine_name not in seen_engs:
                        seen_engs.add(r.engine_name)
                        unique_eng_results.append(r)

                for i in range(len(unique_eng_results)):
                    for j in range(i + 1, len(unique_eng_results)):
                        eng1 = unique_eng_results[i]
                        eng2 = unique_eng_results[j]
                        if eng1.engine_name == eng2.engine_name:
                            continue
                        # Comparing poison@1 against an engine with no clean utility tests
                        # a degenerate ranking, not a robustness difference.
                        if eng1.engine_name in diagnostic_engines or eng2.engine_name in diagnostic_engines:
                            continue

                        pair_key = (f"{att.upper()}", tuple(sorted([eng1.engine_name, eng2.engine_name])))
                        if pair_key in seen_test_pairs:
                            continue
                        seen_test_pairs.add(pair_key)

                        # Align paired traces by query_id
                        traces_b_map = {t.query_id: t for t in eng2.traces}
                        aligned = [(ta, traces_b_map[ta.query_id]) for ta in eng1.traces if ta.query_id in traces_b_map]

                        if att == "clean_baseline":
                            outcomes_a = [getattr(ta, "clean_ground_truth_hit", False) for ta, tb in aligned]
                            outcomes_b = [getattr(tb, "clean_ground_truth_hit", False) for ta, tb in aligned]
                            metric_name = "GT Recall@5 Hit"
                        else:
                            outcomes_a = [ta.has_poison_in_top1 for ta, tb in aligned]
                            outcomes_b = [tb.has_poison_in_top1 for ta, tb in aligned]
                            metric_name = "Retr ASR@1"

                        _record_test(att, eng1.engine_name, eng2.engine_name,
                                     metric_name, outcomes_a, outcomes_b)

        hybrid_results = [r for r in results if "hybrid" in r.engine_name.lower()]
        hybrid_cs = [r for r in hybrid_results if r.attack_type.lower() == "cross_sparse"]
        hybrid_cd = [r for r in hybrid_results if r.attack_type.lower() == "cross_dense"]

        if hybrid_cs and hybrid_cd:
            for eng1 in hybrid_cs:
                for eng2 in hybrid_cd:
                    pair_key = ("CROSS_SPARSE vs CROSS_DENSE", tuple(sorted([eng1.engine_name, eng2.engine_name])))
                    if pair_key in seen_test_pairs:
                        continue
                    seen_test_pairs.add(pair_key)

                    traces_b_map = {t.query_id: t for t in eng2.traces}
                    aligned = [(ta, traces_b_map[ta.query_id]) for ta in eng1.traces if ta.query_id in traces_b_map]

                    outcomes_a = [ta.has_poison_in_top1 for ta, tb in aligned]
                    outcomes_b = [tb.has_poison_in_top1 for ta, tb in aligned]
                    metric_name = "Retr ASR@1"
                    test_res = mcnemar_test_detailed(outcomes_a, outcomes_b)
                    raw_tests.append({
                        "condition": f"CROSS_SPARSE vs CROSS_DENSE ({metric_name})",
                        "eng1": f"{eng1.engine_name} (sparse)",
                        "eng2": f"{eng2.engine_name} (dense)",
                        "discordant": f"({test_res['b']}, {test_res['c']})",
                        "variant": test_res["variant"],
                        "stat_label": test_res["stat_label"],
                        "stat": test_res["stat"],
                        "p_val": test_res["p_val"],
                        "budgets": set(),
                    })

        mcnemar_rows = []
        if raw_tests:
            # Sort by p-value ascending for Holm-Bonferroni
            raw_tests.sort(key=lambda x: x["p_val"])
            m = len(raw_tests)
            max_adj = 0.0

            for k, test in enumerate(raw_tests):
                # Holm-Bonferroni correction
                adj_p = test["p_val"] * (m - k)
                adj_p = max(max_adj, min(1.0, adj_p))
                max_adj = adj_p

                is_sig = adj_p < 0.05
                sig_str = "Yes (p<0.05)" if is_sig else "No"
                budgets_set = test.get("budgets") or set()
                mcnemar_rows.append([
                    test["condition"],
                    ", ".join(f"B={b}" for b in sorted(budgets_set)) if budgets_set else "-",
                    test["eng1"],
                    test["eng2"],
                    test["discordant"],
                    test["variant"],
                    test["stat_label"],
                    format_p_value(test["p_val"]),
                    format_p_value(adj_p),
                    sig_str
                ])

        collapsed_replicates = sum(
            max(0, len(t.get("budgets") or set()) - 1) for t in raw_tests
        )

        if mcnemar_rows:
            mcnemar_table = tabulate(
                mcnemar_rows,
                headers=[
                    "Condition", "Budżety (identyczne wyniki)", "Engine A", "Engine B",
                    "Discordant (b, c)", "Test Variant", "Statistic",
                    "Raw p-value", "Holm-Bonf p-value", "Significant?"
                ],
                tablefmt="github"
            )
        else:
            mcnemar_table = "*Brak pasujących par do testu McNemara.*"

        total_queries = results[0].total_queries if results else 0

        corpus_count_clause = f"{corpus_size:,} autentycznych dokumentów: " if corpus_size is not None else ""
        corpus_desc = (
            f"skali **Real CTI STIX 2.1 ({corpus_count_clause}MITRE ATT&CK STIX 2.1, CTIBench RCM/TAA NeurIPS 2024, CISA KEV, CVE Program cvelistV5, {total_queries} zweryfikowanych zapytań Gold Standard)**"
            if corpus_type == "real"
            else f"skali **Enterprise ({total_queries} zapytań ewaluacyjnych)**"
        )

        exec_mode_desc = (
            "**Tryb Bezkosztowy (Cost-Free Local Benchmark / 100% Local Inference):** Wszystkie 4 silniki RAG (Sparse BM25, Dense FAISS, Hybrid z Rerankerem, GraphRAG) oraz symulacje ataków adwersalnych ewaluowane są w 100% lokalnie na CPU/RAM z wykorzystaniem precyzyjnego cache wektorowego. Koszt wykonania eksperymentu wynosi dokładnie **$0.00** (brak zewnętrznych wywołań płatnych API tokenów LLM)."
        )

        corpus_validity = (
            "1. **Autentyczny Korpus CTI:** Baza wiedzy bazuje na realnych, zweryfikowanych zbiorach: oficjalnym feedzie STIX 2.1 MITRE ATT&CK Enterprise (20k+ relacji encji), CTIBench (NeurIPS 2024 Spotlight), CISA KEV oraz publikowanych rekordach cvelistV5. Zbiór zapytań Gold Standard posiada zweryfikowane etykiety CWE i relacje ATT&CK."
            if corpus_type == "real"
            else "1. **Synthetic Corpus:** The CTI knowledge base is procedurally generated from templates."
        )

        viable_engines = [p["engine"] for p in pareto_ranking if p.get("is_viable", False)]
        non_viable_engines = [p for p in pareto_ranking if not p.get("is_viable", False)]
        pareto_optimal_engines = [p["engine"] for p in pareto_ranking if p.get("is_pareto_optimal", False)]

        if viable_engines:
            v_str = ", ".join(f"**`{e}`**" for e in viable_engines)
            po_str = ", ".join(f"**`{e}`**" for e in pareto_optimal_engines) if pareto_optimal_engines else "brak"
            obs1 = (
                f"1. **Analiza Użyteczności i Frontu Pareto:** Zgodnie z bezwzględnym progiem użyteczności bazowej "
                f"(Clean Recall@5 >= 50% mierzonym wyłącznie na czystym korpusie), architekturami spełniającymi "
                f"kryterium użyteczności w domenie CTI są: {v_str}. Na niezdominowanym froncie Pareto "
                f"w przestrzeni (Clean Recall bazowy ↑ vs średni targeted poison@5 na ramieniu "
                f"referencyjnym i stratach użytecznych ↓) plasują się: {po_str}."
            )
        else:
            obs1 = "1. **Analiza Użyteczności i Frontu Pareto:** Żaden z testowanych silników nie przekroczył bezwzględnego progu minimalnej użyteczności bazowej (Clean Recall@5 >= 50% na czystym korpusie)."

        if non_viable_engines:
            nv_str = ", ".join(f"{p['engine']} ({p['avg_recall']:.1%})" for p in non_viable_engines)
            obs1 += f" Pozostałe silniki ({nv_str}) zostały sklasyfikowane jako `NON_VIABLE`."

        clean_map = {r.engine_name: r for r in results if r.attack_type.lower() == "clean_baseline"}
        sparse_b1_map = {r.engine_name: r for r in results if r.attack_type.lower() in ("sparse_b1", "sparse")}
        topo_b1_map = {r.engine_name: r for r in results if r.attack_type.lower() in ("pure_topological_b1", "pure_topological")}

        if "GraphRAG" in clean_map:
            gr_clean = clean_map["GraphRAG"]
            # Must iterate the explicit strata. A binary "== cve_lookup / != cve_lookup"
            # split silently files the descriptive CVE stratum under ATT&CK.
            per_st = []
            for st in present_strata:
                rec = stratum_recall.get(("GraphRAG", st))
                if rec is not None:
                    per_st.append(f"{STRATUM_LABELS[st]}: {rec:.1%}")
            obs2 = (
                f"2. **Użyteczność GraphRAG:** Po eliminacji błędu kolizji przestrzeni nazw (`doc:` vs `ent:`) "
                f"GraphRAG osiąga Clean Recall@5 = **{gr_clean.clean_recall_top5:.1%}** oraz MRR = **{gr_clean.clean_mrr:.2f}**"
                + (f" ({'; '.join(per_st)})" if per_st else "") + "."
            )
        else:
            obs2 = "2. **Retrakcja Tezy o Niskiej Użyteczności GraphRAG:** Potwierdzono usunięcie błędu kolizji przestrzeni nazw dokumentów i encji w grafie wiedzy STIX 2.1."

        # Observation 3 is stated on the quantities that can carry it: poison@1 restricted to
        # the strata where the engine has utility, the conditional rate, and displacement.
        # The unrestricted aggregate cannot: for GraphRAG it is dominated by a stratum whose
        # clean Recall@5 is 0.0%, where a payload at rank 1 displaced nothing.
        def _restricted_p1(res_obj) -> Optional[float]:
            sts = viable_strata_for(clean_stratum_recall, res_obj.engine_name, MIN_UTILITY_THRESHOLD)
            rates = restricted_poison_rates(res_obj, sts) if sts else None
            return rates["poison_at_1"] if rates else None

        if "GraphRAG" in sparse_b1_map:
            gr_sp = sparse_b1_map["GraphRAG"]
            gr_sp_r = _restricted_p1(gr_sp)
            gr_lo, gr_hi, gr_nt = tie_bounds(gr_sp)
            others = [
                r for r in results
                if r.engine_name != "GraphRAG"
                and r.engine_name not in diagnostic_engines
                and r.attack_type.lower() in ("sparse_b1", "sparse")
            ]
            other_vals = [v for v in (_restricted_p1(r) for r in others) if v is not None]
            other_mean = (sum(other_vals) / len(other_vals)) if other_vals else None

            if gr_sp_r is not None and other_mean is not None:
                verdict = (
                    "niżej niż" if gr_sp_r < other_mean - 1e-9
                    else ("wyżej niż" if gr_sp_r > other_mean + 1e-9 else "na poziomie")
                )
                lex_line = (
                    f"   * **Keyword stuffing:** na stratach, na których GraphRAG ma użyteczność bazową, "
                    f"ładunek leksykalny zajmuje pozycję 1 w **{gr_sp_r:.1%}** zapytań — {verdict} "
                    f"średnia pozostałych silników użytecznych (**{other_mean:.1%}**). "
                    f"Wartość nieograniczona do strat użytecznych wynosi {gr_sp.retrieval_asr_top1:.1%} i jest "
                    f"zawyżona przez stratum o zerowym Recall bazowym."
                )
            else:
                lex_line = (
                    f"   * **Keyword stuffing:** poison@1 = {gr_sp.retrieval_asr_top1:.1%} "
                    f"(brak danych stratyfikacyjnych do ograniczenia do strat użytecznych)."
                )
            if gr_nt:
                lex_line += (
                    f" Uwaga: {gr_nt} zapytań rozstrzygnięto remisem na pozycji 1, więc wartość "
                    f"nieograniczona mieści się w przedziale **{gr_lo:.1%}–{gr_hi:.1%}** zależnie od "
                    f"kierunku rozstrzygnięcia remisu (patrz Sekcja 6)."
                )
        else:
            lex_line = "   * **Keyword stuffing:** scenariusz nieuruchomiony."

        if "GraphRAG" in topo_b1_map:
            gr_tp = topo_b1_map["GraphRAG"]
            gr_tp_r = _restricted_p1(gr_tp)
            per_st_topo = []
            for st in present_strata:
                ts = _stratum_traces(gr_tp, st)
                if ts:
                    v = sum(1 for t in ts if getattr(t, "has_poison_in_top1", False)) / len(ts)
                    per_st_topo.append(f"{STRATUM_LABELS[st]}: {v:.1%}")
            bc_clause = f" przy `bridge_count={bridge_count}`" if bridge_count is not None else ""
            strat_str = "; ".join(per_st_topo) if per_st_topo else "brak danych"
            restricted_str = (
                f" Na stratach użytecznych poison@1 = **{gr_tp_r:.1%}**."
                if gr_tp_r is not None else ""
            )
            # The attack succeeded only if the answer left the window. Both conditional
            # quantities are read off the same denominator as poison@1 cond.
            no_hijack = (gr_tp.retrieval_asr_cond <= 1e-9 and gr_tp.gt_displacement_rate <= 1e-9)
            verdict_str = (
                "**dane nie wykazują przejęcia GraphRAG przez atak czysto topologiczny na "
                "zapytaniach, na które ten silnik w ogóle odpowiada**"
                if no_hijack else
                "przejęcie jest mierzalne również na zapytaniach, na które silnik odpowiada"
            )
            topo_line = (
                f"   * **Atak topologiczny{bc_clause}:** poison@1 zagregowane = "
                f"**{gr_tp.retrieval_asr_top1:.1%}**, ale w rozbiciu stratyfikacyjnym: {strat_str}."
                f"{restricted_str} "
                f"`poison@1 cond` = **{gr_tp.retrieval_asr_cond:.1%}**, "
                f"`GT displaced@5` = **{gr_tp.gt_displacement_rate:.1%}** "
                f"(n={getattr(gr_tp, 'n_displacement_denom', 0)}). "
                f"Zgodnie z regułą z Obserwacji 4 tezę o skuteczności ataku niosą te dwie ostatnie "
                f"wielkości, więc {verdict_str}. "
                f"Wynik zależy od parametru `bridge_count` ataku, nie jest własnością architektury — "
                f"patrz sweep progowy (`scripts/run_bridge_sweep.py`, `bridge_sweep_report.md`)."
            )
        else:
            topo_line = "   * **Atak topologiczny:** nie mierzono (scenariusz nieuruchomiony)."

        obs3 = (
            "3. **Profil Odporności GraphRAG (leksykalny vs strukturalny), w rozbiciu na strata użyteczne:**\n"
            + lex_line + "\n" + topo_line
        )

        attack_results_eval = [r for r in results if r.attack_type.lower() != "clean_baseline"]
        avg_targeted = sum(getattr(r, "retrieval_asr_targeted", 0.0) for r in attack_results_eval) / len(attack_results_eval) if attack_results_eval else 0.0
        avg_untargeted = sum(getattr(r, "retrieval_asr_untargeted", 0.0) for r in attack_results_eval) / len(attack_results_eval) if attack_results_eval else 0.0

        _eligible = [
            r for r in attack_results_eval
            if getattr(r, "n_displacement_denom", 0) > 0 and not getattr(r, "is_diagnostic", False)
        ]
        _p1_vals, _disp_vals = [], []
        for r in _eligible:
            sts = viable_strata_for(clean_stratum_recall, r.engine_name, MIN_UTILITY_THRESHOLD)
            rates = restricted_poison_rates(r, sts) if sts else None
            if rates is None:
                _p1_vals.append(r.retrieval_asr_top1)
                _disp_vals.append(r.gt_displacement_rate)
            else:
                _p1_vals.append(rates["poison_at_1"])
                _disp_vals.append(rates["displaced"])
        avg_disp = sum(_disp_vals) / len(_disp_vals) if _disp_vals else 0.0
        avg_p1 = sum(_p1_vals) / len(_p1_vals) if _p1_vals else 0.0
        avg_p1_unrestricted = (
            sum(r.retrieval_asr_top1 for r in _eligible) / len(_eligible) if _eligible else 0.0
        )
        obs4 = (
            f"4. **Pozycja Ładunku a Wyparcie Odpowiedzi:** Uśredniając po scenariuszach ataku, silnikach "
            f"użytecznych i stratach, na których dany silnik ma użyteczność bazową, ładunek zajmuje pozycję 1 "
            f"w **{avg_p1:.1%}** zapytań, ale odpowiedź znika z całego okna top-5 tylko w **{avg_disp:.1%}** "
            f"zapytań, dla których czysty silnik wcześniej ją znajdował. Te dwie liczby mierzą co innego: "
            f"pierwsza mówi, gdzie w rankingu wylądował ładunek, druga — czy atak faktycznie usunął odpowiedź "
            f"z kontekstu. **Wniosek o skuteczności ataku wolno opierać wyłącznie na drugiej**, i ta sama reguła "
            f"obowiązuje w Obserwacji 3 i w Sekcji 4. Dla porównania: bez ograniczenia do strat użytecznych ta "
            f"sama średnia poison@1 wynosi {avg_p1_unrestricted:.1%}, czyli różnica {avg_p1_unrestricted - avg_p1:+.1%} "
            f"pochodzi wyłącznie ze strat, na których silnik i tak nie znajdował odpowiedzi."
        )

        budgets_fmt = ", ".join(str(b) for b in budgets)

        # Whether a larger budget buys the attacker anything is a measurement, not an
        # assumption. Count engine x vector cells whose per-query outcomes are identical at
        # the smallest and the largest budget: those curves are flat through saturation.
        flat_cells, total_cells = 0, 0
        if len(budgets) >= 2:
            b_lo, b_hi = budgets[0], budgets[-1]
            all_bases = {attack_base(r.attack_type) for r in results if r.attack_type.lower() != "clean_baseline"}
            for eng in {r.engine_name for r in results}:
                for att in all_bases:
                    r_lo = next((r for r in results if r.engine_name == eng and r.attack_type.lower() == f"{att}_b{b_lo}"), None)
                    r_hi = next((r for r in results if r.engine_name == eng and r.attack_type.lower() == f"{att}_b{b_hi}"), None)
                    if not r_lo or not r_hi:
                        continue
                    total_cells += 1
                    hi_map = {t.query_id: t.has_poison_in_top1 for t in r_hi.traces}
                    if all(hi_map.get(t.query_id) == t.has_poison_in_top1 for t in r_lo.traces):
                        flat_cells += 1
        flat_str = (
            f"W **{flat_cells} z {total_cells}** kombinacji silnik × wektor decyzje per-zapytanie są identyczne "
            f"przy B={budgets[0]} i B={budgets[-1]} - w tych komórkach wzrost budżetu nie zmienia niczego, "
            f"a krzywa jest płaska z powodu nasycenia, nie z powodu odporności silnika."
            if total_cells else "Brak par budżetowych do porównania."
        )
        if isolated:
            obs5 = (
                "5. **Weryfikacja Protokołu Izolowanego (Recommendation 3) i Wrażliwości Budżetowej:** Eksperyment przeprowadzono w reżimie izolacji per zapytanie. "
                "Zerowe zanieczyszczenie obcymi ładunkami jest w tym protokole gwarantowane konstrukcyjnie, "
                "więc stanowi asercję poprawności implementacji, a nie wynik empiryczny. "
                f"Krzywe budżetowe $B \\in \\{{{budgets_fmt}\\}}$ zmierzono pod kątem nasycenia. {flat_str}"
            )
        else:
            obs5 = (
                f"5. **Analiza Zanieczyszczenia Tła w Reżimie Współdzielonym:** Zaobserwowano obecność obcego szumu (`retrieval_asr_untargeted` = **{avg_untargeted:.1%}**). "
                "W celu uzyskania nieskażonych krzywych budżetowych zaleca się powtórzenie benchmarku z opcją `--isolated-targets`."
            )

        if diagnostic_engines:
            diag_parts = []
            for eng in sorted(diagnostic_engines):
                cr = clean_map.get(eng)
                if cr is None:
                    continue
                per_st = ", ".join(
                    f"{STRATUM_LABELS[st]}: {stratum_recall[(eng, st)]:.1%}"
                    for st in present_strata if stratum_recall.get((eng, st)) is not None
                )
                distinct = len({d for t in cr.traces for d in t.retrieved_doc_ids})
                slots = sum(len(t.retrieved_doc_ids) for t in cr.traces)
                diag_parts.append(
                    f"**`{eng}`** (Clean Recall@5 = {cr.clean_recall_top5:.1%}; {per_st}; "
                    f"{distinct} unikalnych dokumentów w {slots} slotach top-k)"
                )
            obs6 = (
                "6. **Silniki Poniżej Progu Użyteczności (wyniki diagnostyczne):** "
                + "; ".join(diag_parts)
                + f". Silnik zwracający niemal stałą listę niezwiązanych dokumentów ma wskaźniki `poison@1` opisujące "
                  f"zdegenerowany ranking, a nie odporność, dlatego jest wyłączony z międzysilnikowych średnich "
                  f"(Sekcja 4) i z testów istotności (Sekcja 3.1). Ta sama reguła jest stosowana per stratum, nie "
                  f"tylko per silnik (Sekcja 3, kolumna „Strata wyłączone\"). "
                  f"Obserwacja domenowa: dla zapytań o identyfikatory CVE mały bi-encoder "
                  f"(`{config.DENSE_MODEL_NAME}`) nie rozróżnia unikalnych numerów. **To jednak nie jest rozstrzygnięty "
                  f"wniosek o modelu:** dokumenty CVE są w tym korpusie budowane z jednego szablonu "
                  f"(`real_cti_loader.py`), więc hipoteza „bi-encoder nie koduje identyfikatorów\" jest tu nieodróżnialna "
                  f"od hipotezy „jednorodny szablon dominuje w embeddingu\". Rozstrzygnięcie wymaga wariantu korpusu "
                  f"bez wspólnego prefiksu; do tego czasu jest to obserwacja, nie wyjaśnienie. Praktyczna rekomendacja "
                  f"(indeksowanie leksykalne lub hybrydowe dla lookupu po identyfikatorze) obowiązuje niezależnie od tego, "
                  f"która hipoteza jest prawdziwa."
            )
        else:
            obs6 = (
                "6. **Użyteczność Bazowa:** Wszystkie testowane silniki przekroczyły próg minimalnej użyteczności "
                f"(Clean Recall@5 >= {MIN_UTILITY_THRESHOLD:.0%}), więc żaden nie został oznaczony jako diagnostyczny."
            )

        sec5_obs = [obs1, obs2, obs3, obs4, obs5, obs6]
        sec5_text = "\n".join(sec5_obs)

        # ---------------------------------------------------------------- Section 6 inputs
        # Everything below is a measured limitation, computed here rather than asserted, so a
        # future run cannot keep the prose while the number underneath it changes.

        # Rank-1 ties. Reported per engine at its worst scenario: this is the width the Wilson
        # interval does not cover.
        tie_rows = []
        for eng in unique_engines:
            worst = None
            for r in results:
                if r.engine_name != eng or r.attack_type.lower() == "clean_baseline":
                    continue
                lo_t, hi_t, n_tie = tie_info[(r.engine_name, r.attack_type)]
                if n_tie and (worst is None or (hi_t - lo_t) > (worst[2] - worst[1])):
                    worst = (r.attack_type.upper(), lo_t, hi_t, n_tie, r.retrieval_asr_top1)
            if worst:
                tie_rows.append([eng, worst[0], f"{worst[4]:.1%}",
                                 f"{worst[1]:.1%}-{worst[2]:.1%}", worst[3]])
        if tie_rows:
            tie_table = tabulate(
                tie_rows,
                headers=["RAG Engine", "Najgorszy scenariusz", "poison@1 raportowane",
                         "Zakres wg rozstrzygnięcia remisu", "Zapytania z remisem"],
                tablefmt="github"
            )
            full_groups = all(getattr(r, "tie_bounds_source", "rank12") == "full_group" for r in results)
            source_note = (
                "Zakresy policzono na pełnych grupach remisowych: cała grupa na pozycji 1 oraz grupa "
                f"na granicy pozycji {config.TOP_K} (przebieg z `--log-ties`)."
                if full_groups else
                "Zakresy liczone wyłącznie z pary pozycji 1–2; pełna grupa remisowa może je poszerzyć "
                "(pełne grupy zapisuje przebieg z `--log-ties`)."
            )
            disp_table = ""
            if full_groups:
                disp_rows = []
                for eng in unique_engines:
                    worst_d = None
                    for r in results:
                        if r.engine_name != eng or r.attack_type.lower() == "clean_baseline":
                            continue
                        lo_d = getattr(r, "gt_displacement_tie_lower", None)
                        hi_d = getattr(r, "gt_displacement_tie_upper", None)
                        if lo_d is None or hi_d is None or hi_d - lo_d <= 0:
                            continue
                        if worst_d is None or (hi_d - lo_d) > (worst_d[2] - worst_d[1]):
                            worst_d = (r.attack_type.upper(), lo_d, hi_d, r.gt_displacement_rate)
                    if worst_d:
                        disp_rows.append([eng, worst_d[0], f"{worst_d[3]:.1%}",
                                          f"{worst_d[1]:.1%}-{worst_d[2]:.1%}"])
                if disp_rows:
                    disp_table = "\n\n" + tabulate(
                        disp_rows,
                        headers=["RAG Engine", "Najgorszy scenariusz",
                                 f"GT displaced@{config.TOP_K} raportowane", "Zakres wg rozstrzygnięcia remisu"],
                        tablefmt="github"
                    )
            tie_limitation = (
                "6. **Nieoznaczoność remisów rankingowych (`poison@1` nie jest estymatorem punktowym "
                "dla silników remisujących):** silnik grafowy przypisuje wielu dokumentom identyczny "
                "wynik, a `sorted(key=(-score, doc_id))` rozstrzyga remis kolejnością identyfikatorów. "
                "Dla remisu przecinającego granicę poison/clean o wartości metryki decyduje więc "
                "porządek alfabetyczny (`POISON_…` vs `CVE-…`), a nie funkcja scoringu. Przedział "
                "Wilsona w Sekcji 2 obejmuje wyłącznie błąd próbkowania i **nie zawiera tej "
                f"nieoznaczoności**; poniższa tabela podaje jej szerokość. {source_note}\n\n"
                + tie_table + disp_table
            )
        else:
            tie_limitation = (
                "6. **Remisy rankingowe:** w tym przebiegu żaden scenariusz nie zawiera remisu na "
                "pozycji 1 przecinającego granicę poison/clean, więc `poison@1` jest estymatorem "
                "punktowym."
            )

        # Constant context slots: a document present regardless of the question, found per
        # question template and judged by whether it ranks above the gold document.
        slot_findings = constant_slot_findings(results)
        if slot_findings:
            # Findings in strata below the utility floor are excluded from every aggregate, so
            # they are counted rather than listed; the audit gate prints them in full.
            viable_f = [f for f in slot_findings if f["viable"]]
            other_f = [f for f in slot_findings if not f["viable"]]
            off_str = "; ".join(
                f"**{f['engine']}** / {STRATUM_LABELS.get(f['stratum'], f['stratum'])} / szablon "
                f"`{f['template']}` (n={f['n']}): `{f['doc']}` w top-{config.TOP_K} dla {f['share']:.0%} "
                f"pytań, nad złotym dokumentem w {f['above_gold']}"
                for f in viable_f
            ) or "brak w stratach użytecznych"
            if other_f:
                off_str += (
                    f"; ponadto {len(other_f)} przypadków w parach silnik–stratum poniżej progu "
                    f"użyteczności ({', '.join(sorted({f['engine'] for f in other_f}))}), wyłączonych "
                    f"z agregatów (pełna lista: `scripts/audit_checks.py`, check K4)"
                )
            harmful = [f for f in slot_findings if f["above_gold"] and f["viable"]]
            verdict = (
                f"W {len(harmful)} z tych przypadków stały dokument wyprzedza złoty dokument w stratum "
                f"użytecznym; tam atakujący potrzebuje o jeden ładunek mniej, by wypchnąć odpowiedź "
                f"z okna top-{config.TOP_K}, a `GT displaced@{config.TOP_K}` jest zawyżone przez konstrukcję "
                f"pytania, nie przez atak."
                if harmful else
                f"Żaden z nich nie wyprzedza złotego dokumentu w stratum użytecznym, więc nie zmienia "
                f"żadnej raportowanej wielkości."
            )
            constant_slot_limitation = (
                f"7. **Stałe sloty kontekstu (dokument obecny niezależnie od pytania, liczone w grupach "
                f"jednego szablonu):** {off_str}. Gdy pytania grupy mają wspólne wszystkie słowa poza "
                f"identyfikatorem, sloty poza złotym dokumentem zajmują dokumenty najlepiej pasujące do "
                f"tych wspólnych słów, a więc te same przy każdym pytaniu. Przy wyszukiwaniu po kluczu z "
                f"jednym złotym dokumentem jest to cecha strukturalna, nie wada silnika. Pomiar zniekształca "
                f"dopiero stały dokument **nad** złotym. {verdict}"
            )
        else:
            constant_slot_limitation = (
                "7. **Stałe sloty kontekstu:** żaden dokument nie okupuje slotu top-k w >90% pytań "
                "żadnej grupy szablonu."
            )

        # Latency: Limitation 4 promises median and IQR, so the table has to exist.
        lat_rows = []
        for r in results:
            if r.attack_type.lower() != "clean_baseline":
                continue
            lat_rows.append([
                r.engine_name,
                f"{r.latency_median_ms:.1f}",
                f"{r.latency_iqr_ms:.1f}",
                f"{r.avg_retrieval_latency_ms:.1f}",
            ])
        latency_table = tabulate(
            lat_rows,
            headers=["RAG Engine", "Mediana (ms)", "IQR (ms)", "Średnia (ms)"],
            tablefmt="github"
        ) if lat_rows else "*Brak pomiarów latencji.*"

        # Reproducibility manifest.
        if run_manifest:
            man_rows = [[k, str(v)] for k, v in sorted(run_manifest.items())]
            manifest_table = tabulate(man_rows, headers=["Pozycja", "Wartość"], tablefmt="github")
        else:
            manifest_table = (
                "*Brak manifestu przebiegu. Uruchom benchmark przez "
                "`scripts/run_comparison_benchmark.py`, który zapisuje `run_manifest.json`.*"
            )

        # ASR_cond denominators differ per engine because each is conditioned on that engine's
        # own clean baseline. Spelling them out stops the column being read as like-for-like.
        _denoms = {}
        for r in results:
            if r.attack_type.lower() == "clean_baseline":
                continue
            _denoms.setdefault(r.engine_name, getattr(r, "n_displacement_denom", 0))
        cond_denoms = ", ".join(f"{eng}: n={n}" for eng, n in _denoms.items()) or "n/a"

        types = (run_manifest or {}).get("corpus_doc_types")
        if types:
            total_docs = sum(types.values()) or 1
            top_types = sorted(types.items(), key=lambda kv: -kv[1])[:4]
            corpus_composition = (
                "The corpus is not uniform across the tasks it is used for: "
                + ", ".join(f"{k} {v:,} ({v / total_docs:.1%})" for k, v in top_types)
                + ". A stratum whose answers live in a small document class is therefore a "
                  "retrieval problem over that class, embedded in a much larger corpus of "
                  "another class, and the headline corpus size overstates its difficulty."
            )
        else:
            corpus_composition = (
                "The corpus mixes document classes in very unequal proportions, so the headline "
                "corpus size does not describe the effective difficulty of any single stratum."
            )

        mcnemar_note = (
            f"Rodzina testów: **{len(raw_tests)}** po zwinięciu **{collapsed_replicates}** "
            f"replikatów budżetowych o identycznych wektorach wyników per zapytanie. "
            f"Replikaty zwinięto, bo cztery wiersze opisujące ten sam wynik liczyłyby jedno "
            f"ustalenie czterokrotnie i sztucznie zaostrzały korektę Holma. "
            f"Hipoteza zerowa jest międzysilnikowa: test porównuje `poison@1` dwóch silników "
            f"o różnej użyteczności bazowej, więc odrzucenie H0 oznacza różnicę w łącznym "
            f"efekcie „kompetencja wyszukiwania + odporność\", a nie w samej odporności. "
            f"Silniki diagnostyczne są z testów wyłączone."
        )

        protocol_desc = (
            "**Protokół Ewaluacji: Izolowany Indeks per Zapytanie (Recommendation 3 / Isolated Target Protocol)**. "
            f"Dla każdego zapytania testowego $Q_i$ indeks wyszukiwania zawiera wyłącznie czysty korpus oraz dedykowane "
            f"ładunki zatrute wygenerowane dla tego zapytania ($B \\in \\{{{budgets_fmt}\\}}$). W indeksie nie znajdują się żadne ładunki "
            "zaadresowane do innych zapytań ($Q_j, j \\ne i$), co całkowicie eliminuje sztuczną saturację okna kontekstowego "
            "obcym szumem (`retrieval_asr_untargeted = 0.0%`) i zapewnia niezakłócony pomiar wrażliwości na budżet ataku."
            if isolated else
            "**Protokół Ewaluacji: Współdzielony Indeks Korpusu (Shared Corpus Index)**. "
            "Wszystkie wygenerowane ładunki zatrute dla wszystkich zapytań umieszczone są w jednej współdzielonej bazie. "
            "W celu rzetelności pomiaru sukces ataku mierzony jest jako celowane przejęcie `retrieval_asr_targeted`, "
            "a zanieczyszczenie obcymi ładunkami raportowane jest odrębnie jako `retrieval_asr_untargeted`."
        )

        isolated_note = (
            "\n\n*Protokół izolowany (Recommendation 3): Indeks dla każdego zapytania testowego zawierał wyłącznie czysty korpus i ładunki wygenerowane dla tego zapytania. Wskaźnik zanieczyszczenia tła (`retrieval_asr_untargeted`) wynosi 0.0%.*"
            if isolated else ""
        )

        budget_note = (
            f"\n\nW protokole izolowanym (Recommendation 3) krzywe budżetowe odzwierciedlają wrażliwość na liczbę wstrzykniętych wariantów ładunku ($B \\in \\{{{budgets_fmt}\\}}$) bez efektu saturacji okna obcymi zatruciami. {flat_str}"
            if isolated else
            "\n\nW protokole współdzielonym wzrost budżetu sumuje zatrucia ze wszystkich zapytań ($B \\times N$), co może prowadzić do saturacji okna kontekstowego obcym szumem."
        )

        if "GraphRAG" in topo_b1_map:
            gr_tp = topo_b1_map["GraphRAG"]
            bc_str = f"bridge_count={bridge_count}" if bridge_count is not None else "the configured bridge_count"
            sec6_topo_desc = (
                f"3. **GraphRAG Subgraph Traversal & Structural Attack Surface:** GraphRAG walks multi-hop "
                f"subgraphs over STIX 2.1 networks. The purely topological attack reaches rank 1 on "
                f"{gr_tp.retrieval_asr_top1:.1%} of all queries at {bc_str}, but that aggregate is carried by a "
                f"stratum in which GraphRAG's own clean Recall@5 is below the utility floor. Restricted to the "
                f"queries this engine actually answers, `poison@1 cond` = {gr_tp.retrieval_asr_cond:.1%} and "
                f"`GT displaced@5` = {gr_tp.gt_displacement_rate:.1%} "
                f"(n={getattr(gr_tp, 'n_displacement_denom', 0)}). **This run therefore neither establishes nor "
                f"refutes degree-normalization immunity**: `bridge_count` is a free parameter of the attack and the "
                f"outcome is a function of where it sits relative to the crossover threshold "
                f"n > 72 + sqrt(5184 + 144*deg0) (bridges have degree 3; the payload's score through one anchoring "
                f"entity never exceeds 1/6). See `scripts/run_bridge_sweep.py` and `bridge_sweep_report.md`; "
                f"any claim about GraphRAG's structural robustness has to cite the sweep, not a single point on it."
            )
        else:
            sec6_topo_desc = (
                f"3. **GraphRAG Subgraph Traversal:** GraphRAG employs multi-hop subgraph traversal over STIX 2.1 networks. "
                f"Pure Topological attack against graph structure: not measured (scenario not executed)."
            )

        sec6_protocol_desc = (
            "5. **Evaluation Protocol & Context Isolation:** The benchmark was executed under the isolated per-query protocol (Recommendation 3), ensuring 0.0% foreign context contamination. All budget curves represent true marginal attack scaling."
            if isolated else
            "5. **Evaluation Protocol & Shared Index Contamination:** In shared corpus mode, multi-query poison payloads are pooled, which can inflate untargeted contamination at higher budgets. Isolated evaluation protocol is available via `--isolated-targets`."
        )

        # Conditionally render ablation references
        ablations = []
        if (query_echo is False) or any(getattr(t, "query_echo", True) is False for r in results for t in r.traces):
            ablations.append("ablacji echa zapytania (`query_echo=False`)")
        if any("topological" in r.attack_type.lower() for r in results):
            ablations.append("izolacji warstwy grafowej (`PureTopologicalPoisonAttacker`)")
        ablation_clause = f", a także {', '.join(ablations)}" if ablations else ""

        doc_title = "# 🔬 Raport z Badania Odporności Warstwy Wyszukiwania RAG na Ataki Corpus Poisoning (Retrieval Robustness - Real CTI STIX 2.1)"
        sec2_title = "## 2. Zbiorcza Macierz Wyników (Retrieval Robustness Benchmark)"

        _nl = chr(10)
        scope_banner = _nl.join([
            "> [!IMPORTANT]",
            "> ### Zakres pomiaru i co z niego nie wynika",
            "> ",
            "> * **Warstwa wyszukiwania, bez generacji.** Etap LLM nie jest uruchamiany "
            "(`llm_stage_ran = False`) — to świadoma granica zakresu. Dlatego metryki nazywają się "
            "`poison@1` / `poison@5`, a nie ASR: w literaturze (PoisonedRAG, Zou i in.) ASR to udział "
            "pytań, dla których **model wygenerował** odpowiedź atakującego. Tu mierzona jest pozycja "
            "ładunku w rankingu.",
            "> * **Wyparcie odpowiedzi mierzone osobno.** `GT displaced@5` podaje, dla ilu zapytań "
            "odpowiedź znikęła z okna kontekstowego. Ładunek na pozycji 1 przy odpowiedzi wciąż "
            "obecnej na pozycji 2 nie odbiera generatorowi dostępu do prawdy. **Tezę o skuteczności "
            "ataku niosą wyłącznie `GT displaced@5` i `poison@1 cond`**, nie `poison@1`.",
            "> * **Próg użyteczności obowiązuje per stratum.** Ładunek na pozycji 1 w stratum, "
            "w którym czysty silnik i tak nie znajdował odpowiedzi, niczego nie wypiera. Wszystkie "
            "średnie międzyscenariuszowe (Sekcja 3 i 4) liczone są wyłącznie na stratach, na których "
            "dany silnik osiąga Clean Recall@5 >= 50%; wartości nieograniczone pozostają w Sekcji 2.",
            "> * **Brak obrony jest założeniem badania.** Żaden filtr wejściowy ani higiena indeksu nie "
            "są włączone. Wszystkie wartości opisują zatem system bez zabezpieczeń i stanowią **górne "
            "ograniczenie** podatności.",
            "> * **Model adwersarza:** scenariusze celowane operują w reżimie wyroczni "
            "(*Worst-Case / Oracle*): atakujący zna treść zapytania, docelową asercję fałszującą "
            "**oraz `key_terms`, które dla zapytań relacyjnych zawierają nazwy dokumentów-odpowiedzi**. "
            "Wektor `blackbox_category` jest najsłabszym testowanym adwersarzem (zna wyłącznie "
            "kategorię pytań). Uwaga: „górna” i „dolna granica” opisują siłę modelu zagrożeń, "
            "a nie porządek zmierzonych wartości — wektory white-box o innej konstrukcji "
            "(`entity_swap`, `pure_topological`) wypadają miejscami niżej niż `blackbox_category`.",
            "> * **Ramię query-echo jest osobnym testem skrajnym.** Dosłowne doklejenie pytania ofiary "
            "do ładunku raportowane jest jako odrębna kolumna górnego ograniczenia i **nie wchodzi** "
            "do uśrednionej odporności w rankingu.",
            "> * **Arytmetyka okna:** przy budżecie B równym rozmiarowi okna k spadek Clean Recall@5 "
            "do zera jest konsekwencją zajęcia wszystkich slotów, a nie załamania algorytmu.",
        ])
        md_content = f"""{doc_title}

{scope_banner}

## 1. Wstęp i Metodologia Badawcza
Eksperyment bada i porównuje odporność 4 kluczowych architektur wyszukiwania RAG:
* **Sparse (BM25 Okapi)**
* **Dense (FAISS + SentenceTransformers `{config.DENSE_MODEL_NAME}`)**
* **Hybrid + Cross-Encoder Reranker (BM25 + FAISS + RRF + `{config.RERANKER_MODEL_NAME}`)**
* **GraphRAG (NetworkX Degree-Normalized Entity-Relation Subgraph Traversal na grafie STIX 2.1)**

w {corpus_desc} pod kątem następujących wektorów zatruwania bazy wiedzy (*corpus poisoning*):
1. **BM25 Keyword Stuffing / TF-IDF Saturation** — nasycenie leksykalne terminami kluczowymi zapytania.
2. **Dense Semantic Embedding Alignment** — konstrukcja w duchu PoisonedRAG, semantycznie spójna, bez powtórzeń.
3. **Hybrid Dual-Constraint Evasion** — ładunek przechodzący jednocześnie przez BM25 i cross-encoder.
4. **Graph Bridge Injection** — wstrzyknięcie syntetycznych węzłów-mostków podnoszących wagę przejścia wielohopowego. *Nie jest to implementacja GRAGPoison (arXiv:2501.14050) ani LogicPoison (arXiv:2604.02954); obie te prace celowo unikają syntetycznych węzłów.*
5. **Graph Entity Swap** — podmiana encji z zachowaniem typu, w duchu LogicPoison: bez dodawania nowych węzłów, oba końce relacji istnieją w korpusie.
6. **Pure Topological Poisoning** — manipulacja wyłącznie topologią, bez terminów zapytania w tekście.
7. **Black-Box Category Poisoning** — najsłabszy testowany model zagrożeń: atakujący zna wyłącznie kategorię zapytań, żadnego identyfikatora ofiary. Uwaga: „najsłabszy adwersarz" nie znaczy „najniższy zmierzony `poison@1`" — wektory white-box o innej konstrukcji wypadają miejscami niżej.
8. **Black-Box Topic+Entity** — wariant historyczny, korzystający z identyfikatora ofiary (nie jest więc adwersarzem blind).

oraz walidacji krzyżowej (*cross-attack robustness*), analizy warunkowej $ASR_{{\\text{{cond}}}}$ (*Conditional ASR*){ablation_clause}.

{protocol_desc}

Procedura pomiarowa została zremediowana metrologicznie: wyeliminowano błędy kolizji przestrzeni nazw GraphRAG, zaimplementowano separację celowanego przejęcia (`retrieval_asr_targeted`) od obcego zanieczyszczenia, a ocenę odporności oparto na analizie frontu Pareto z bezwzględnym progiem użyteczności (Recall@5 $\\ge$ 50%).

{exec_mode_desc}
Wyniki zawierają 95% przedziały ufności Wilsona (*Wilson Score Interval*) oraz testy istotności statystycznej McNemara.

---

{sec2_title}

*Kolumna **ASR_cond** ($ASR_{{\\text{{cond}}}}$) mierzy skuteczność przejęcia pozycji Top-1 wraz z 95% przedziałem ufności Wilsona wyłącznie na podzbiorze zapytań ($n_{{\\text{{cond}}}}$), dla których czysty silnik w warunkach bazowych odnalazł właściwy dokument Ground Truth (clean hit > 0).*{isolated_note}

{md_table}

---

## 2.1 Pełna Macierz Podatności Krzyżowej (Cross-Vulnerability Matrix), B=1

Tabela przedstawia `poison@1` dla każdego silnika w zderzeniu z każdym wektorem ataku, **przy budżecie B=1**. Pozostałe budżety są w Sekcji 2.3. Wartości nie są ograniczone do strat użytecznych — rozbicie stratyfikacyjne jest w Sekcji 2.2, a wnioski agregowane w Sekcji 3 liczone są wyłącznie na stratach użytecznych.

{cross_matrix_table}

---

## 2.2 Złożoność Domenowa CTI: Pełna Stratyfikacja Zadań (Domain Task Stratification)

W domenie CTI ewaluacja uśredniona zaciera diametralnie różne mechanizmy wyszukiwania. Poniżej przedstawiono pełną stratyfikację wyników na rozłączne zadania.

**Recall@5 i Hit@5 są raportowane osobno.** To dwie różne wielkości: Recall@5 jest ułamkowy (`|zwrócone ∩ GT| / |GT|`), a Hit@5 binarny (czy trafiono cokolwiek). Różnią się wszędzie tam, gdzie zapytanie ma więcej niż jeden dokument docelowy, więc podawanie jednej pod nazwą drugiej rozjeżdża tabelę zbiorczą z tabelami stratyfikacji.

**Kolumna `Max GT displaced@5`** podaje najwyższy w danym stratum odsetek zapytań, dla których czysty silnik znajdował odpowiedź, a po ataku nie ma jej nigdzie w oknie top-5. To jest miara faktycznego wyparcia odpowiedzi; `poison@1` mówi wyłącznie o tym, gdzie w rankingu wylądował ładunek.

**Kolumny `poison@1` w tabelach stratyfikacji podają wartości dla B=1.** Status `NON_VIABLE` stratum oznacza, że wszystkie wartości `poison@1` w tym wierszu opisują ranking, który i tak nie zawierał odpowiedzi — dlatego takie wiersze są wyłączone ze średnich w Sekcjach 3 i 4.

### A. Użyteczność Bazowa w Podziale na Zadania
{cat_split_table}

{stratum_sections}

---

## 2.3 Krzywe Ataku (Attack Budget Curves)

Wpływ budżetu atakującego (liczby wstrzykniętych dokumentów per zapytanie $B$) na szansę przejęcia top-1 kontekstu:
* **Reżim sub-saturacji ($B \\le 2$ przy oknie $k=5$):** Liczba wstrzykniętych ładunków zatrutych nie przekracza połowy okna kontekstowego wyszukiwania ($k=5$). Pozwala to zbadać naturalną selektywność silnika i zdolność do zachowania czystego dokumentu Ground Truth.
* **Reżim stress-testu saturacyjnego ($B \\ge 3$ przy oknie $k=5$):** Większość okna kontekstowego ($>50\\%$) może zostać zdominowana przez ładunki zatrute, testując odporność w warunkach bezpośredniej presji ilościowej.{budget_note}

{budget_curves_table}

---

## 2.4 Latencja Wyszukiwania (Clean Baseline)

Pomiar zegarem monotonicznym `time.perf_counter()`; podano medianę i rozstęp ćwiartkowy po odrzuceniu pierwszego zapytania scenariusza. **Uwaga:** w protokole izolowanym każdy pomiar zawiera również przebudowę indeksu dla danego zapytania, więc są to czasy end-to-end tego protokołu, a nie czysty czas wyszukiwania w indeksie utrzymywanym na stałe.

{latency_table}

---

## 3. Empiryczny Ranking Odporności Architektur (Wyliczony Algorytmicznie)

*Zakres obowiązywania rankingu: wartości uśredniono **wyłącznie po stratach, na których dany silnik osiąga Clean Recall@5 ≥ 50%** (kolumna „Strata wyłączone" podaje, co odpadło) oraz **wyłącznie po ramieniu referencyjnym**; ramię query-echo, jako test skrajny, ma własną kolumnę i nie wchodzi do średniej. Sam podział zbioru zapytań (po ~1/3 na stratum) pozostaje arbitralny, więc ranking jest kompozytem poglądowym — rozstrzygające są tabele stratyfikacji w Sekcji 2.2.*

{ranking_table}

---

## 3.1 Statistical Significance of Pairwise Architecture Differences (McNemar's Test)

Pairwise McNemar comparisons are limited to scenarios sharing the same attack vector or baseline condition.

{mcnemar_note}

{mcnemar_table}

---

## 4. Skuteczność Wektorów Ataków (Attack Vector Efficacy)

Uśrednione po silnikach nie-diagnostycznych i po stratach użytecznych każdego z nich. Tabela jest **uporządkowana według `GT displaced@5`**, czyli według tego, czy atak faktycznie usunął odpowiedź z okna kontekstowego; `poison@1` podano obok jako wielkość pomocniczą. Kolumna `Silniki (n)` podaje, ilu silników dotyczy średnia — jest to liczba jednocyfrowa, więc średnie te są orientacyjne.

**Wiersze w reżimie `B>=k` są wyłączone z porządkowania i zepchnięte na dół tabeli.** Przy budżecie równym rozmiarowi okna same ładunki wystarczą, by je zapełnić, więc wyparcie jest tam konsekwencją arytmetyki, a nie skuteczności ataku — mierzone na wspólnym wsparciu silników wyparcie skacze z ok. 2% przy B=3 do ok. 100% przy B=5, podczas gdy `poison@5` nie zmienia się wcale. Porównawcze twierdzenia o sile wektorów wolno opierać wyłącznie na wierszach sub-saturacyjnych.

{attack_table}

---

## 5. Kluczowe Obserwacje i Wnioski Naukowe

{sec5_text}

---

## 6. Limitations and Threats to Validity

{corpus_validity}
2. **White-Box Attack Oracle vs Weakest Tested Adversary:** The benchmark evaluates white-box targeted adversaries with query access and a category-level adversary that never touches a victim identifier. Note that the targeted adversaries are handed `key_terms`, which for the relational stratum contain the *names of the answer documents* (`real_query_loader.py` builds them as `[entity] + gold`). Their payloads therefore repeat the gold answer, which is a stronger oracle than "access to the query and the target assertion". `entity_swap` deliberately filters the gold answer out of its anchors, so part of the ASR gap between it and the lexical vectors is a difference in answer leakage, not only in attack construction.
2a. **No Defenses By Design:** No input filtering, deduplication, perplexity screening or index hygiene is enabled at any stage. This is a deliberate scope boundary, not an omission: every figure describes an undefended retrieval stage and is therefore an upper bound. Numbers here are not comparable to work that reports defended pipelines.
2b. **Retrieval-Stage Metrics:** `poison@1` and `poison@5` are payload-ranking measurements, not end-to-end attack success. `GT displaced@5` and `poison@1 cond` are the quantities that carry any claim about an attack "succeeding". Note that `poison@1 cond` is conditioned on each engine's *own* clean baseline, so its denominator differs per engine ({cond_denoms}); the column compares rates computed on different subsets of queries and is not a like-for-like cross-engine comparison.
{sec6_topo_desc}
4. **Metrological Latency & Local Determinism:** Timing uses high-resolution monotonic `time.perf_counter()`, discarding the first query of each scenario, and is reported as median and IQR in Section 2.4. Retrieval is deterministic and the query and corpus samples are drawn with a fixed seed (42), so a re-run on this machine against the cached corpus reproduces every figure exactly.
{sec6_protocol_desc}
{tie_limitation}
{constant_slot_limitation}
8. **Query-set construction (what the utility numbers actually measure):** The three strata are not equally hard, and two of the three are string-matching tasks. In the exact-match stratum the answer's own identifier appears verbatim in the question, making it a key lookup. In the descriptive stratum the question is a literal substring of the target document, making it near-duplicate matching. Only the relational stratum requires traversal, and its answer set is derived from the same STIX edges GraphRAG walks, so part of the graph engine's advantage there is built into the task. The relational query pool is additionally filtered to edges with at most 3 answer documents (`MAX_ANSWER_DOCS`), which removes the hardest attribution questions. Every baseline utility figure, and therefore the >= 50% viability floor and the Pareto front resting on it, should be read against these constructions rather than as general CTI retrieval quality.
9. **Corpus composition and provenance:** {corpus_composition} A third party rebuilding the corpus from the upstream sources will not obtain this exact snapshot: the MITRE bundle is fetched from a moving branch, and the cvelistV5 sample from whatever the latest release is at build time. The run manifest below records what this run actually used; without pinning those snapshots, cross-machine bit-identical replication is not claimed.

{manifest_table}

10. **Statistical reporting:** Wilson intervals are reported per row and are **not** corrected for the number of rows in Section 2; they describe sampling error over the query sample for that one cell, and should be read descriptively rather than as simultaneous coverage. Only the McNemar family in Section 3.1 carries a multiplicity correction (Holm-Bonferroni). All intervals cover sampling error only, never the tie indeterminacy in item 6 or the attack-parameter dependence in item 3.
"""

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(md_content, encoding="utf-8")
        return md_content

    @staticmethod
    def save_generation_traces(results: List[EngineBenchmarkResult], output_file: Path):
        all_traces = []
        for r in results:
            for t in r.traces:
                all_traces.append(t.__dict__)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(all_traces, indent=2, ensure_ascii=False), encoding="utf-8")
