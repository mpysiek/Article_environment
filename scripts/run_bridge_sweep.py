#!/usr/bin/env python3
"""Sweeps the bridge count of the topological graph attack.

Why this exists: `PureTopologicalPoisonAttacker` has exactly one free parameter,
`bridge_count`, and it decides the headline result. GraphRAG scores a genuine 1-hop
document at 2.0/sqrt(deg) and gives the poison, reached over n synthetic bridges, 2-hop
credit of 0.5/(deg_bridge * deg) per bridge. Every bridge has degree 3 in the directed
multigraph -- the anchor->bridge edge, the bridge->payload edge and the payload's MENTIONS
edge back to the bridge -- so the payload scores n * 0.5/(3*deg) = n/(6*deg).

The tempting algebra -- n/(6*deg) > 2.0/sqrt(deg), so n > 12*sqrt(deg) -- is wrong, because
injecting the bridges *raises the degree of the anchoring entity itself*: the attack adds n
edges to it, so deg = deg0 + n on both sides. Solving the self-consistent form

    n / (6 * (deg0 + n))  >  2.0 / sqrt(deg0 + n)
    =>  n^2 - 144n - 144*deg0 > 0
    =>  n  >  72 + sqrt(5184 + 144*deg0)

puts the crossover at n = 146.9 for a degree-3 entity (every CVE exact-match anchor in the v2
run), n = 150 for degree 6 and n = 201 for degree 80 -- several times what the naive formula
predicts, and much less sensitive to degree. The same expression has a ceiling: n/(6*(deg0+n))
stays below 1/6 per anchoring entity for any n, so a clean document that collects more than
that from the query's other entities cannot be displaced by adding bridges.

(Versions of this script before the v3 correction assumed degree-2 bridges and printed
n > 32 + sqrt(1024 + 64*deg0), which places the crossover at roughly half its real value.)

Either way the point stands: reporting one n as "GraphRAG is immune at top-1" states a property
of that constant, not of the architecture. This script measures the curve.

Runs GraphRAG only -- the other engines see no graph structure, so the sweep says nothing
about them.
"""
import argparse
import json
import math
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from tabulate import tabulate

from src.config import config, refuse_archive_dir
from src.corpus.real_cti_loader import RealCTILoader
from src.corpus.real_query_loader import build_real_gold_queries, QUERY_SETS
from src.engines.retrievers import GraphRAGRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.evaluation.stages import execute_isolated_retrieval

DEFAULT_BRIDGES = [10, 20, 40, 80, 160, 320]

STRATUM_BY_CATEGORY = {"cve_lookup": "exact", "cve_descriptive": "descr"}


def stratum_of(category: str) -> str:
    return STRATUM_BY_CATEGORY.get(category or "", "attack")


def query_entity_degrees(engine: GraphRAGRetriever, queries) -> Dict[str, float]:
    """Degree of the graph entities each query anchors on, on the clean graph."""
    degrees: Dict[str, float] = {}
    for q in queries:
        matched = engine._extract_query_entities(q.query_text)
        degs = []
        for ent in matched:
            node = ent if engine.graph.has_node(ent) else f"ent:{ent}"
            if engine.graph.has_node(node):
                degs.append(engine.graph.degree(node))
        degrees[q.id] = float(statistics.median(degs)) if degs else 0.0
    return degrees


def predicted_crossover(deg0: float) -> float:
    """Bridge count above which the payload outranks a genuine 1-hop document of the anchor.

    Positive root of n^2 - 144n - 144*deg0 = 0, from n/(6*(deg0+n)) > 2/sqrt(deg0+n): bridges
    have degree 3 and the anchor's degree grows by n (module docstring). 144 = (2*2*3)^2.
    """
    return 72.0 + math.sqrt(5184.0 + 144.0 * deg0)


def main():
    parser = argparse.ArgumentParser(description="Sweep bridge_count for the topological graph attack.")
    parser.add_argument("--queries", type=int, default=150)
    parser.add_argument("--num_cves", type=int, default=24000)
    parser.add_argument("--bridges", type=int, nargs="+", default=DEFAULT_BRIDGES)
    parser.add_argument("--budget", type=int, default=1,
                        help="Payloads per query. Keep at 1: the sweep is about bridge count, "
                             "not about window saturation.")
    parser.add_argument("--out-dir", type=str, default=None)
    parser.add_argument("--query-set", choices=list(QUERY_SETS), default="v2",
                        help="Question templates (see src/corpus/real_query_loader.py).")
    args = parser.parse_args()

    out_dir = refuse_archive_dir(Path(args.out_dir) if args.out_dir else config.REPORTS_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 78)
    print("[*] BRIDGE-COUNT SWEEP: PureTopologicalPoisonAttacker vs GraphRAG")
    print("=" * 78)

    clean_docs = RealCTILoader().load_full_real_corpus(target_cves=args.num_cves)
    queries = build_real_gold_queries(n=args.queries, query_set=args.query_set)
    print(f"[+] Corpus: {len(clean_docs):,} documents | Queries: {len(queries)}")

    engine = GraphRAGRetriever()
    engine.build_index(clean_docs)
    degrees = query_entity_degrees(engine, queries)
    nonzero = [d for d in degrees.values() if d > 0]
    med_deg = statistics.median(nonzero) if nonzero else 0.0
    # Self-consistent threshold: the bridges inflate the anchor degree they are measured
    # against, so deg is deg0 + n on both sides of the comparison.
    predicted = predicted_crossover(med_deg) if med_deg else float("nan")
    print(f"[+] Median degree of matched query entities: {med_deg:.0f} "
          f"-> predicted crossover n > {predicted:.0f}")

    poison_mgr = CorpusPoisonManager(query_echo=False)
    poison_mgr.fit_corpus(clean_docs)

    rows = []
    records = []
    for n in args.bridges:
        t0 = time.time()
        poison_mgr.set_bridge_count(n)
        payloads = poison_mgr.generate_isolated_poison_payloads(
            queries, "pure_topological", attack_budget=args.budget
        )
        outputs, _ = execute_isolated_retrieval(
            engine=engine, clean_docs=clean_docs, poison_payloads=payloads,
            queries=queries, top_k=config.TOP_K
        )
        p1 = sum(1 for q in queries if outputs[q.id] and outputs[q.id][0].is_poisoned)
        p5 = sum(1 for q in queries if any(r.is_poisoned for r in outputs[q.id][:5]))

        # Where the payload does reach rank 1, how large was the anchoring entity? This is
        # what turns the sweep into a statement about the threshold rather than a curve.
        won_degs = [degrees[q.id] for q in queries
                    if outputs[q.id] and outputs[q.id][0].is_poisoned and degrees[q.id] > 0]
        lost_degs = [degrees[q.id] for q in queries
                     if outputs[q.id] and not outputs[q.id][0].is_poisoned and degrees[q.id] > 0]
        # Split by stratum. A payload reaching rank 1 on a query the clean engine never
        # answered is a different event from one that displaces a real answer, and the
        # aggregate hides which of the two the sweep is picking up.
        by_st = {}
        for q in queries:
            st = stratum_of(q.category)
            hit = bool(outputs[q.id]) and outputs[q.id][0].is_poisoned
            by_st.setdefault(st, []).append(hit)
        st_str = "  ".join(f"{k}={sum(v)/len(v):.0%}" for k, v in sorted(by_st.items()))

        rows.append([
            n,
            f"{p1 / len(queries):.1%}",
            f"{p5 / len(queries):.1%}",
            st_str,
            f"{statistics.median(won_degs):.0f}" if won_degs else "-",
            f"{statistics.median(lost_degs):.0f}" if lost_degs else "-",
            f"{time.time() - t0:.1f}s",
        ])
        records.append({
            "bridge_count": n,
            "poison_at_1": p1 / len(queries),
            "poison_at_5": p5 / len(queries),
            "median_degree_won": statistics.median(won_degs) if won_degs else None,
            "median_degree_lost": statistics.median(lost_degs) if lost_degs else None,
            "poison_at_1_by_stratum": {k: sum(v) / len(v) for k, v in by_st.items()},
        })
        print(f"   [+] bridges={n:<5} poison@1={p1 / len(queries):6.1%}  poison@5={p5 / len(queries):6.1%}")

    table = tabulate(
        rows,
        headers=["bridge_count", "poison@1", "poison@5", "poison@1 per stratum",
                 "median deg (attack won)", "median deg (attack lost)", "time"],
        tablefmt="github",
    )
    print()
    print(table)

    payload = {
        "queries": len(queries),
        "corpus_size": len(clean_docs),
        "budget": args.budget,
        "median_query_entity_degree": med_deg,
        "predicted_crossover_n": predicted,
        "sweep": records,
    }
    (out_dir / "bridge_sweep_results.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    (out_dir / "bridge_sweep_report.md").write_text(
        "# Bridge-Count Sweep: Topological Graph Attack vs GraphRAG\n\n"
        f"Korpus: {len(clean_docs):,} dokumentow | Zapytania: {len(queries)} | Budzet B={args.budget}\n\n"
        f"Mediana stopnia encji zapytania: **{med_deg:.0f}**, "
        f"stad przewidywany prog przejscia: **n > {predicted:.0f}** "
        "(warunek samouzgodniony: n/(6*(deg0+n)) > 2.0/sqrt(deg0+n), czyli n > 72 + sqrt(5184 + 144*deg0); kazdy most ma stopien 3, a wynik ladunku przez jedna kotwice nie przekracza 1/6. Naiwne n > 12*sqrt(deg) pomija to, ze wstrzykniete krawedzie same podnosza stopien encji kotwiczacej).\n\n"
        f"{table}\n\n"
        "Pojedyncza wartosc `bridge_count` nie opisuje odpornosci architektury, tylko polozenie "
        "wzgledem tego progu. Kolumna per stratum jest tu istotniejsza niz mediana stopnia: "
        "ladunek na pozycji 1 w stratum, w ktorym czysty silnik i tak nie znajdowal odpowiedzi, to inne zdarzenie niz wyparcie realnej odpowiedzi -- mediany stopnia nalezy czytac dopiero po tym rozbiciu.\n",
        encoding="utf-8",
    )
    print(f"\n[+] Saved: {out_dir / 'bridge_sweep_results.json'}")
    print(f"[+] Saved: {out_dir / 'bridge_sweep_report.md'}")


if __name__ == "__main__":
    main()
