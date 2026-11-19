#!/usr/bin/env python3
"""Ties in the RRF cut of the Hybrid-Reranker candidate pool.

Hybrid-Reranker fuses the top 10 of BM25 and of the dense engine by reciprocal rank fusion and
keeps the 10 best fused candidates for the cross-encoder. Candidates found by one engine only,
at the same rank, have identical RRF scores, and the cut keeps them in insertion order: BM25
before dense. When the last place of the pool falls inside such a pair, the dense candidate is
left out although its score equals that of the BM25 candidate that stays.

The tie bounds recorded with --log-ties do not cover this: they describe ties among the
cross-encoder scores of the pool, not the membership of the pool. This script counts, from the
stored candidate pools, the query-scenario lists in which the cut was decided by that order.
The excluded candidate itself is not recorded. It can be named only when it stood at dense
rank 1-5, because the Dense-FAISS traces of the same scenario hold the dense top 5.

Read-only: nothing is written.

Usage:
    python scripts/rrf_pool_ties.py --in-dir outputs/reports/v3
"""
import argparse
import collections
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.evaluation.strata import MIN_UTILITY_THRESHOLD, clean_stratum_recall, stratum_of

HYBRID = "Hybrid-Reranker"
DENSE = "Dense-FAISS"


def cut_tie_rank(pool):
    """BM25 rank j of a pool member that ties with the dense rank-j candidate left out of the pool.

    Returns None when the cut did not fall inside an equal-score pair.
    """
    lowest = min(p["rrf_score"] for p in pool)
    for p in pool:
        if abs(p["rrf_score"] - lowest) > 1e-12:
            continue
        if p["bm25_rank"] is not None and p["dense_rank"] is None:
            j = p["bm25_rank"]
            if not any(q["dense_rank"] == j for q in pool):
                return j
    return None


def analyse(data):
    viable = {st for (eng, st), rec in clean_stratum_recall(data).items()
              if eng == HYBRID and rec >= MIN_UTILITY_THRESHOLD}
    dense = {d["attack_type"]: {t["query_id"]: t for t in d["traces"]}
             for d in data if d["engine_name"] == DENSE}
    out = {"lists": 0, "cut_ties": 0, "identified": 0, "unidentified": 0,
           "excluded": collections.Counter(), "changes_outcome": []}
    for d in data:
        if d["engine_name"] != HYBRID:
            continue
        for t in d["traces"]:
            pool = t.get("candidate_pool") or []
            if not pool:
                raise SystemExit("No candidate pools in these traces: the run was not recorded with --log-ties.")
            out["lists"] += 1
            j = cut_tie_rank(pool)
            if j is None:
                continue
            out["cut_ties"] += 1
            dense_top = dense[d["attack_type"]][t["query_id"]]["retrieved_doc_ids"]
            if j > len(dense_top):
                out["unidentified"] += 1
                continue
            out["identified"] += 1
            excluded = dense_top[j - 1]
            gold = set(t["ground_truth_doc_ids"])
            kind = "payload" if excluded.startswith("POISON_") else ("gold" if excluded in gold else "other")
            out["excluded"][kind] += 1
            if kind != "other":
                st = stratum_of(t["query_category"])
                out["changes_outcome"].append({
                    "scenario": d["attack_type"], "query": t["query_id"], "excluded": kind,
                    "stratum": st, "viable_for_hybrid": st in viable,
                })
    return out


def main():
    ap = argparse.ArgumentParser(description="Ties in the RRF cut of the Hybrid-Reranker candidate pool.")
    ap.add_argument("--in-dir", required=True, help="Results directory of a run recorded with --log-ties.")
    args = ap.parse_args()
    data = json.loads((Path(args.in_dir) / "comparison_benchmark_results.json").read_text(encoding="utf-8"))
    r = analyse(data)
    print(f"Hybrid-Reranker query-scenario lists:            {r['lists']}")
    print(f"Pool cut decided by the order of equal RRF scores: {r['cut_ties']} "
          f"({r['cut_ties'] / r['lists']:.1%})")
    print(f"  excluded candidate identifiable (dense rank <= 5): {r['identified']} "
          f"-> {dict(r['excluded'])}")
    print(f"  excluded candidate not recorded:                  {r['unidentified']}")
    for c in r["changes_outcome"]:
        print(f"  excluded {c['excluded']} document: {c['scenario']} / {c['query']} "
              f"({c['stratum']}, viable for {HYBRID}: {c['viable_for_hybrid']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
