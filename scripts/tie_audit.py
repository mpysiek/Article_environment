#!/usr/bin/env python3
"""Tie-aware re-audit of the deterministic engines (GraphRAG and Sparse-BM25).

Why this exists
---------------
The stored traces of a run record only whether ranks 1 and 2 have identical scores
(`top1_is_score_tie`). That is not enough to bound the metrics of an engine that produces
large groups of identical scores:

* poison@1 depends on the order of the *whole* rank-1 tie group, not only on ranks 1-2;
* GT displaced@5 and clean Hit@5 depend on the order of the tie group that straddles the
  rank-5 boundary, which the traces do not record at all.

GraphRAG and Sparse-BM25 need no neural model, so they can be re-run deterministically with a
deep ranking and their scores. This script does that under the same isolated per-query
protocol, checks that the re-run reproduces the stored top-5 lists, and records for every
query and scenario what the metric would be under *any* ordering of the tied documents.

Outputs (in --out-dir):
  tie_audit_<engine>.json          per-query tie-aware records for every scenario
  bridge_sweep_tieaware.json       PURE_TOPOLOGICAL bridge-count sweep (GraphRAG, B=1)
                                   with rank-1 tie groups and rank-5 boundary recorded

Usage:
  python scripts/tie_audit.py --in-dir outputs/reports/v3 --query-set v3 --engines graphrag sparse
  python scripts/tie_audit.py --in-dir outputs/reports/v3 --query-set v3 --sweep-only
"""
import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.corpus.real_cti_loader import RealCTILoader
from src.corpus.real_query_loader import build_real_gold_queries, QUERY_SETS
from src.engines.retrievers import GraphRAGRetriever, BM25Retriever
from src.attacks.poisoning import CorpusPoisonManager
from src.config import refuse_archive_dir
from src.evaluation.strata import stratum_of

# Reference arm (8 vectors) plus the query-echo arm, exactly as in run_comparison_benchmark.py.
VECTORS: List[Tuple[str, str, bool]] = [
    ("sparse", "sparse", False),
    ("dense", "dense", False),
    ("hybrid", "hybrid", False),
    ("graph", "graph", False),
    ("entity_swap", "entity_swap", False),
    ("blackbox_category", "blackbox_category", False),
    ("blackbox", "blackbox", False),
    ("pure_topological", "pure_topological", False),
    ("dense_echo", "dense", True),
]
BUDGETS = [1, 2, 3, 5]
SWEEP_BRIDGES = [10, 20, 40, 80, 100, 120, 140, 146, 147, 150, 160, 320]
TOP_K = 5


def deep_retrieve(engine, query_text: str, min_depth: int = 200):
    """Ranking deep enough to contain the complete rank-1 and rank-5 tie groups."""
    depth = min_depth
    while True:
        res = engine.retrieve(query_text, top_k=depth)
        if len(res) < depth:
            return res  # engine returned everything it scored
        boundary = res[min(TOP_K, len(res)) - 1].score
        if res[-1].score < boundary and res[-1].score < res[0].score:
            return res
        depth *= 4


def tie_record(res, gold: set) -> Dict:
    """Per-query bounds over every ordering of tied documents."""
    top5 = [r.doc_id for r in res[:TOP_K]]
    rec = {"top5": top5}
    if not res:
        rec.update(p1=False, p1_lo=False, p1_hi=False, hit=False, hit_lo=False, hit_hi=False,
                   recall=0.0, recall_lo=0.0, recall_hi=0.0, n_rank1_tie=0, n_boundary_tie=0)
        return rec
    # Rank 1: any document of the rank-1 tie group can be placed first.
    s1 = res[0].score
    g1 = [r for r in res if r.score == s1]
    rec["p1"] = bool(res[0].is_poisoned)
    rec["p1_lo"] = all(r.is_poisoned for r in g1)
    rec["p1_hi"] = any(r.is_poisoned for r in g1)
    rec["n_rank1_tie"] = len(g1)
    # Rank-5 boundary: documents scoring above the rank-5 score are certainly in top-5; the
    # tie group at that score competes for the remaining `slots`.
    last = res[min(TOP_K, len(res)) - 1].score
    above = [r for r in res if r.score > last]
    group = [r for r in res if r.score == last]
    slots = TOP_K - len(above)
    if len(res) < TOP_K:
        slots = len(group)
    g_above = sum(1 for r in above if r.doc_id in gold)
    g_group = sum(1 for r in group if r.doc_id in gold)
    ng_group = len(group) - g_group
    in_top5 = sum(1 for d in top5 if d in gold)
    rec["hit"] = in_top5 > 0
    rec["hit_hi"] = g_above > 0 or (g_group > 0 and slots >= 1)
    rec["hit_lo"] = g_above > 0 or (g_group > 0 and ng_group < slots)
    denom = max(1, len(gold))
    rec["recall"] = in_top5 / denom
    rec["recall_lo"] = (g_above + max(0, min(g_group, slots - ng_group))) / denom
    rec["recall_hi"] = (g_above + min(g_group, slots)) / denom
    rec["n_boundary_tie"] = len(group) if len(group) > slots else 0
    return rec


def run_scenario(engine, clean_docs, queries, payloads: Optional[Dict[str, list]]) -> Dict[str, Dict]:
    out = {}
    for q in queries:
        extra = payloads.get(q.id, []) if payloads else []
        engine.build_index(clean_docs + extra if extra else clean_docs)
        res = deep_retrieve(engine, q.query_text)
        out[q.id] = tie_record(res, set(q.ground_truth_doc_ids))
    return out


def load_stored(in_dir: Path) -> Dict[Tuple[str, str], Dict[str, List[str]]]:
    path = in_dir / "comparison_benchmark_results.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {(d["engine_name"], d["attack_type"]): {t["query_id"]: t["retrieved_doc_ids"] for t in d["traces"]}
            for d in data}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--in-dir", type=str, required=True,
                    help="Results directory of the run to audit, e.g. outputs/reports/v3.")
    ap.add_argument("--out-dir", type=str, default=None)
    ap.add_argument("--engines", nargs="+", default=["graphrag", "sparse"], choices=["graphrag", "sparse"])
    ap.add_argument("--bridge-count", type=int, default=40)
    ap.add_argument("--sweep-only", action="store_true")
    ap.add_argument("--no-sweep", action="store_true")
    ap.add_argument("--query-set", choices=list(QUERY_SETS), default="v2",
                    help="Question templates; must match the run in --in-dir for the top-5 check.")
    args = ap.parse_args()

    in_dir = Path(args.in_dir)
    out_dir = refuse_archive_dir(args.out_dir if args.out_dir else in_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    clean_docs = RealCTILoader().load_full_real_corpus(target_cves=24000)
    queries = build_real_gold_queries(n=150, query_set=args.query_set)
    cats = {q.id: stratum_of(q.category) for q in queries}
    stored = load_stored(in_dir)
    print(f"[+] Corpus {len(clean_docs):,} docs | {len(queries)} queries | stored traces: {bool(stored)}")

    mgr = CorpusPoisonManager(query_echo=False, bridge_count=args.bridge_count)
    mgr.fit_corpus(clean_docs)

    if not args.sweep_only:
        for eng_key in args.engines:
            engine = GraphRAGRetriever() if eng_key == "graphrag" else BM25Retriever()
            engine.build_index(clean_docs)
            name = engine.name
            scenarios = {}
            mismatches = {}
            t0 = time.time()
            recs = run_scenario(engine, clean_docs, queries, None)
            scenarios["clean_baseline"] = recs
            for key, att, echo in VECTORS:
                for b in BUDGETS:
                    sk = f"{key}_b{b}"
                    mgr.set_bridge_count(args.bridge_count)
                    pay = mgr.generate_isolated_poison_payloads(queries, att, attack_budget=b, query_echo=echo)
                    scenarios[sk] = run_scenario(engine, clean_docs, queries, pay)
                    print(f"   [{name}] {sk:<24} {time.time() - t0:7.1f}s", flush=True)
            for sk, recs in scenarios.items():
                ref = stored.get((name, sk))
                if ref:
                    mismatches[sk] = sum(1 for qid, r in recs.items() if r["top5"] != ref.get(qid))
            payload = {
                "engine": name,
                "query_set": args.query_set,
                "bridge_count": args.bridge_count,
                "top_k": TOP_K,
                "query_stratum": cats,
                "top5_mismatches_vs_stored": mismatches,
                "scenarios": scenarios,
            }
            fname = out_dir / f"tie_audit_{eng_key}.json"
            fname.write_text(json.dumps(payload), encoding="utf-8")
            bad = {k: v for k, v in mismatches.items() if v}
            print(f"[+] {name}: saved {fname}; top-5 mismatches vs stored traces: {bad or 'none'}")

    if not args.no_sweep:
        engine = GraphRAGRetriever()
        engine.build_index(clean_docs)
        clean = run_scenario(engine, clean_docs, queries, None)
        sweep = {}
        for n in SWEEP_BRIDGES:
            mgr.set_bridge_count(n)
            pay = mgr.generate_isolated_poison_payloads(queries, "pure_topological", attack_budget=1)
            sweep[str(n)] = run_scenario(engine, clean_docs, queries, pay)
            p1 = sum(r["p1"] for r in sweep[str(n)].values()) / len(queries)
            print(f"   [sweep] bridges={n:<4} poison@1={p1:6.1%}", flush=True)
        payload = {"engine": engine.name, "attack": "pure_topological", "budget": 1,
                   "query_set": args.query_set,
                   "query_stratum": cats, "clean_baseline": clean, "sweep": sweep}
        (out_dir / "bridge_sweep_tieaware.json").write_text(json.dumps(payload), encoding="utf-8")
        print(f"[+] Saved {out_dir / 'bridge_sweep_tieaware.json'}")


if __name__ == "__main__":
    main()
