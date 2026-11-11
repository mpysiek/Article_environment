"""Retrieval protocol of a benchmark scenario.

`execute_isolated_retrieval` runs the per-query isolated protocol (--isolated-targets),
`execute_shared_retrieval` the shared-index one, and `deep_retrieve` the untimed deep
ranking used for tie bounds (--log-ties).

Until 1.3.2 this module also held the file handoff between stage A (retrieval and
generation), stage B (LLM judge over the Batch API) and stage C (evaluation). The benchmark
has no generation stage, so that code was removed; it is in the git history at bee8fe6.
"""

import time
from typing import List, Dict, Any, Tuple, Optional

from src.corpus.dataset import RetrievalResult, GoldQuery


def deep_retrieve(engine: Any, query_text: str, top_k: int = 5, min_depth: int = 50) -> List[RetrievalResult]:
    """Ranking deep enough to contain the complete rank-1 tie group and the complete tie group
    at the rank-k boundary.

    The official top-k ranking is unaffected: this is a second, untimed retrieval whose only
    purpose is to bound tie-dependent metrics. Engines that score a fixed candidate pool (the
    hybrid reranker scores ten candidates) return fewer results than requested, which ends the
    loop; for them the groups are complete within the pool, which is all the engine ranks.
    """
    # Engines that keep the full pool they just ranked (the hybrid reranker) hand it over
    # directly: re-running the cross-encoder would double the dominant cost of a run.
    pool = getattr(engine, "last_pool", None)
    if pool is not None and getattr(engine, "last_pool_query", None) == query_text:
        return list(pool)
    depth = max(min_depth, top_k + 1)
    while True:
        res = engine.retrieve(query_text, top_k=depth)
        if len(res) < depth:
            return res
        first = res[0].score
        boundary = res[min(top_k, len(res)) - 1].score
        if res[-1].score != first and res[-1].score != boundary:
            return res
        depth *= 4


def execute_isolated_retrieval(
    engine: Any,
    clean_docs: List[Any],
    poison_payloads: Dict[str, List[Any]],
    queries: List[GoldQuery],
    top_k: int = 5,
    deep_outputs: Optional[Dict[str, List[RetrievalResult]]] = None,
) -> Tuple[Dict[str, List[RetrievalResult]], Dict[str, float]]:
    """Executes the Recommendation 3 isolated per-query retrieval protocol.

    For each evaluation query Q_i:
      1. An isolated index instance is prepared containing clean_docs plus ONLY the poison
         documents generated for Q_i (zero foreign poisons).
      2. Retrieves top_k results for Q_i.
    Returns:
      (retrieval_outputs, retrieval_latencies)
    """
    retrieval_outputs: Dict[str, List[RetrievalResult]] = {}
    retrieval_latencies: Dict[str, float] = {}

    for q in queries:
        q_poisons = poison_payloads.get(q.id, [])
        index_docs = clean_docs + q_poisons if q_poisons else clean_docs
        engine.build_index(index_docs)

        t0 = time.perf_counter()
        results = engine.retrieve(q.query_text, top_k=top_k)
        ret_latency_ms = (time.perf_counter() - t0) * 1000.0

        retrieval_outputs[q.id] = results
        retrieval_latencies[q.id] = ret_latency_ms

        # Optional tie logging: an untimed, deeper retrieval on the same index state, so the
        # latency and the official top-k stay exactly what they are without logging.
        if deep_outputs is not None:
            deep_outputs[q.id] = deep_retrieve(engine, q.query_text, top_k=top_k)

    return retrieval_outputs, retrieval_latencies


def execute_shared_retrieval(
    engine: Any,
    corpus: List[Any],
    queries: List[GoldQuery],
    top_k: int = 5
) -> Tuple[Dict[str, List[RetrievalResult]], Dict[str, float]]:
    """Executes shared-index retrieval across all queries."""
    engine.build_index(corpus)
    retrieval_outputs: Dict[str, List[RetrievalResult]] = {}
    retrieval_latencies: Dict[str, float] = {}

    for q in queries:
        t0 = time.perf_counter()
        results = engine.retrieve(q.query_text, top_k=top_k)
        ret_latency_ms = (time.perf_counter() - t0) * 1000.0

        retrieval_outputs[q.id] = results
        retrieval_latencies[q.id] = ret_latency_ms

    return retrieval_outputs, retrieval_latencies
