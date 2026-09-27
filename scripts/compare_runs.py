#!/usr/bin/env python3
"""Compares two benchmark runs scenario by scenario and query by query.

Written for the v2 control re-run: a re-run of the same query set with tie logging switched on
must reproduce every point metric and every top-5 list of the archived run. Anything that
differs is listed, so a mismatch is an explicit finding rather than a rounding impression.

Latencies are compared nowhere: they depend on the machine's load, not on the ranking.

Usage:
  python scripts/compare_runs.py --a outputs/reports/v2 --b outputs/reports/v2_rerun
"""
import argparse
import json
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

#: Point metrics that must agree exactly when the rankings agree.
POINT_FIELDS = [
    "total_queries", "retrieval_asr_top1", "retrieval_asr_top3", "retrieval_asr_top5",
    "retrieval_asr_cond", "gt_displacement_rate", "n_displacement_denom",
    "clean_recall_top5", "clean_mrr", "retrieval_asr_targeted", "retrieval_asr_untargeted",
    "graph_fallback_rate",
]


def load(d: Path):
    data = json.loads((d / "comparison_benchmark_results.json").read_text(encoding="utf-8"))
    return {(r["engine_name"], r["attack_type"]): r for r in data}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--a", required=True, help="reference run directory (e.g. outputs/reports/v2)")
    ap.add_argument("--b", required=True, help="run to check against it")
    ap.add_argument("--out", default=None, help="JSON summary (default: <b>/compare_vs_<a-name>.json)")
    args = ap.parse_args()
    a_dir, b_dir = Path(args.a), Path(args.b)
    A, B = load(a_dir), load(b_dir)

    only_a = sorted(set(A) - set(B))
    only_b = sorted(set(B) - set(A))
    metric_diffs, list_diffs, query_diffs = [], [], []
    n_lists = 0
    for key in sorted(set(A) & set(B)):
        ra, rb = A[key], B[key]
        for f in POINT_FIELDS:
            if ra.get(f) != rb.get(f):
                metric_diffs.append({"engine": key[0], "scenario": key[1], "field": f,
                                     "a": ra.get(f), "b": rb.get(f)})
        ta = {t["query_id"]: t for t in ra["traces"]}
        tb = {t["query_id"]: t for t in rb["traces"]}
        if set(ta) != set(tb):
            query_diffs.append({"engine": key[0], "scenario": key[1],
                                "only_a": sorted(set(ta) - set(tb)), "only_b": sorted(set(tb) - set(ta))})
        for qid in sorted(set(ta) & set(tb)):
            n_lists += 1
            if ta[qid]["retrieved_doc_ids"] != tb[qid]["retrieved_doc_ids"]:
                list_diffs.append({"engine": key[0], "scenario": key[1], "query_id": qid,
                                   "a": ta[qid]["retrieved_doc_ids"], "b": tb[qid]["retrieved_doc_ids"]})

    summary = {
        "a": str(a_dir), "b": str(b_dir),
        "scenarios_compared": len(set(A) & set(B)),
        "scenarios_only_in_a": only_a, "scenarios_only_in_b": only_b,
        "top5_lists_compared": n_lists,
        "top5_lists_different": len(list_diffs),
        "point_metric_differences": len(metric_diffs),
        "query_set_differences": query_diffs,
        "metric_diffs": metric_diffs[:500],
        "list_diffs": list_diffs[:500],
    }
    out = Path(args.out) if args.out else b_dir / f"compare_vs_{a_dir.name}.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Scenarios compared: {summary['scenarios_compared']} "
          f"(only in A: {len(only_a)}, only in B: {len(only_b)})")
    print(f"Top-5 lists compared: {n_lists}; different: {len(list_diffs)}")
    print(f"Point-metric differences: {len(metric_diffs)}")
    for d in metric_diffs[:20]:
        print(f"  {d['engine']:<16} {d['scenario']:<24} {d['field']}: {d['a']} -> {d['b']}")
    for d in list_diffs[:10]:
        print(f"  {d['engine']:<16} {d['scenario']:<24} {d['query_id']}: {d['a']} -> {d['b']}")
    print(f"Saved: {out}")
    identical = not (only_a or only_b or metric_diffs or list_diffs or query_diffs)
    print("RESULT: IDENTICAL" if identical else "RESULT: DIFFERENCES FOUND")
    return 0 if identical else 1


if __name__ == "__main__":
    sys.exit(main())
