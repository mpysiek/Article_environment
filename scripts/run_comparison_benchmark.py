#!/usr/bin/env python3
"""
CTI RAG Corpus Poisoning Benchmark: Comparing 4 RAG Architectures
(Sparse BM25, Dense FAISS, Hybrid with Reranker, GraphRAG)
on authentic CTI STIX 2.1 knowledge base (24,000 authentic documents)
under adversarial corpus poisoning attacks.

Measures the retrieval layer only: deterministic, local, no API calls. There is no
generation stage (removed in 1.3.2; see CHANGELOG.md).
"""
import sys
import json
import time
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.config import config
from src.corpus.dataset import build_cti_knowledge_base, build_gold_benchmark_queries, CTIDocument, GoldQuery
from src.corpus.real_cti_loader import RealCTILoader
from src.corpus.real_query_loader import build_real_gold_queries, QUERY_SETS
from src.engines.retrievers import BM25Retriever, DenseFAISSRetriever, HybridRerankRetriever, GraphRAGRetriever, BaseRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.evaluation.metrics import Evaluator, EngineBenchmarkResult
from src.evaluation.stages import execute_isolated_retrieval, deep_retrieve
from src.visualization.reporter import BenchmarkReporter

def build_run_manifest(
    clean_docs: List[CTIDocument],
    queries: List[GoldQuery],
    bridge_count: int,
    budgets: List[int],
    isolated_targets: bool,
    query_echo: bool,
    seed: int = 42,
    query_set: str = "v2",
    log_ties: bool = False
) -> Dict[str, Any]:
    """Records what this run actually used, so a later reader is not left guessing.

    The corpus is assembled from a moving upstream branch (MITRE) and whatever the latest
    cvelistV5 release happens to be, and the requirements are floor-pinned, so "seed 42"
    alone does not make a run reproducible off this machine. A content hash of the corpus
    plus the resolved package versions is what actually identifies the snapshot.
    """
    import hashlib
    import platform
    from importlib import metadata as importlib_metadata

    h = hashlib.sha256()
    for d in clean_docs:
        h.update(d.id.encode("utf-8"))
        h.update(b"\x00")
    corpus_fingerprint = h.hexdigest()[:16]

    doc_types: Dict[str, int] = {}
    for d in clean_docs:
        doc_types[d.doc_type] = doc_types.get(d.doc_type, 0) + 1

    versions = {}
    for pkg in ("torch", "transformers", "sentence-transformers", "faiss-cpu",
                "rank-bm25", "networkx", "numpy"):
        try:
            versions[pkg] = importlib_metadata.version(pkg)
        except Exception:
            versions[pkg] = "not installed"

    strata: Dict[str, int] = {}
    for q in queries:
        strata[q.category] = strata.get(q.category, 0) + 1

    # Which questions were asked, not only how many: two query sets share ids but not texts.
    hq = hashlib.sha256()
    for q in queries:
        hq.update(q.id.encode("utf-8"))
        hq.update(b"\x00")
        hq.update(q.query_text.encode("utf-8"))
        hq.update(b"\x00")
    query_fingerprint = hq.hexdigest()[:16]

    return {
        "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "seed": seed,
        "corpus_documents": len(clean_docs),
        "corpus_id_fingerprint_sha256_16": corpus_fingerprint,
        "corpus_doc_types": doc_types,
        "queries": len(queries),
        "query_set": query_set,
        "query_fingerprint_sha256_16": query_fingerprint,
        "query_categories": strata,
        "log_ties": log_ties,
        "attack_bridge_count": bridge_count,
        "attack_budgets": budgets,
        "isolated_targets": isolated_targets,
        "query_echo_default": query_echo,
        "dense_model": config.DENSE_MODEL_NAME,
        "reranker_model": config.RERANKER_MODEL_NAME,
        "top_k": config.TOP_K,
        "package_versions": versions,
    }


def run_benchmark_matrix(
    corpus_mode: str = "real",
    num_cves: int = 24000,
    num_queries: int = 150,
    query_echo: bool = False,
    include_topological: bool = False,
    isolated_targets: bool = False,
    budgets: Optional[List[int]] = None,
    out_dir: Optional[Path] = None,
    bridge_count: int = 40,
    query_set: str = "v2",
    log_ties: bool = False
) -> List[EngineBenchmarkResult]:
    if budgets is None:
        budgets = [1, 2, 3, 5]
    reports_dir = Path(out_dir) if out_dir else config.REPORTS_DIR

    print("=" * 80)
    print("[*] CTI RAG CORPUS POISONING BENCHMARK: 4 ARCHITECTURES COMPARISON")
    print("=" * 80)
    print(f"[*] Corpus Mode:      {corpus_mode.upper()} ({num_cves} documents target)")
    print(f"[*] Protocol:         {'ISOLATED PER-QUERY (Rec 3)' if isolated_targets else 'SHARED CORPUS'}")
    print(f"[*] Number of Queries:{num_queries}")
    print(f"[*] Attack Budgets:   {budgets}")
    print(f"[*] Query Echo:       {query_echo}")
    print(f"[*] Bridge Count:     {bridge_count} (graph/topological attack free parameter)")
    print(f"[*] Dense Model:      {config.DENSE_MODEL_NAME}")
    print(f"[*] Reranker Model:   {config.RERANKER_MODEL_NAME}")
    print(f"[*] Retrieval Top-K:  {config.TOP_K}")
    print(f"[*] Query Set:        {query_set}")
    print(f"[*] Tie Logging:      {'ON (deep ranking per query, untimed)' if log_ties else 'off'}")

    start_total_time = time.time()

    # 1. Dataset & Queries
    print("\n[1/5] Loading CTI Ground Truth Dataset & Benchmark Queries...")
    if corpus_mode == "real":
        clean_docs = RealCTILoader().load_full_real_corpus(target_cves=num_cves)
        queries = build_real_gold_queries(n=num_queries, query_set=query_set)
        print(f"   [+] Loaded {len(clean_docs):,} authentic CTI documents (MITRE ATT&CK STIX 2.1, CTIBench RCM/TAA, CISA KEV, cvelistV5)")
        print(f"   [+] Loaded {len(queries)} verified Gold Benchmark queries with grounded ground truth")
    else:
        clean_docs = build_cti_knowledge_base()
        all_queries = build_gold_benchmark_queries()
        queries = all_queries[:num_queries]
        print(f"   [+] Loaded {len(clean_docs)} synthetic CTI documents")
        print(f"   [+] Configured {len(queries)} synthetic Gold Benchmark queries")

    # 2. Initialize Models & Clients
    print("\n[2/5] Initializing 4 Retrieval Engines & Poison Manager...")
    bm25 = BM25Retriever()
    dense = DenseFAISSRetriever(model_name=config.DENSE_MODEL_NAME)
    hybrid = HybridRerankRetriever(bm25, dense, reranker_name=config.RERANKER_MODEL_NAME)
    graph = GraphRAGRetriever()

    engines: Dict[str, BaseRetriever] = {
        "Sparse-BM25": bm25,
        "Dense-FAISS": dense,
        "Hybrid-Reranker": hybrid,
        "GraphRAG": graph
    }

    poison_mgr = CorpusPoisonManager(query_echo=query_echo, bridge_count=bridge_count)
    # EntitySwapPoisonAttacker draws its decoys from the real corpus, so it must see it
    # before any payload is generated.
    poison_mgr.fit_corpus(clean_docs)
    all_results: List[EngineBenchmarkResult] = []
    clean_hits_by_engine: Dict[str, Dict[str, bool]] = {}

    def evaluate_scenario(
        engine_name: str,
        attack_type: str,
        docs: Optional[List[CTIDocument]] = None,
        poison_payloads: Optional[Dict[str, List[CTIDocument]]] = None,
        clean_hits: Optional[Dict[str, bool]] = None
    ) -> EngineBenchmarkResult:
        engine = engines[engine_name]
        # Deep rankings for tie bounds. Filled by an untimed second retrieval on the same index
        # state, so neither the latencies nor the official top-k depend on this switch.
        deep_outputs: Optional[Dict[str, list]] = {} if log_ties else None

        if isolated_targets and poison_payloads is not None:
            retrieval_outputs, retrieval_latencies = execute_isolated_retrieval(
                engine=engine,
                clean_docs=clean_docs,
                poison_payloads=poison_payloads,
                queries=queries,
                top_k=config.TOP_K,
                deep_outputs=deep_outputs
            )
        else:
            engine.build_index(docs)
            retrieval_outputs = {}
            retrieval_latencies = {}
            for q in queries:
                # Step A: Retrieval
                t_ret0 = time.perf_counter()
                results = engine.retrieve(q.query_text, top_k=config.TOP_K)
                ret_latency_ms = (time.perf_counter() - t_ret0) * 1000.0

                retrieval_outputs[q.id] = results
                retrieval_latencies[q.id] = ret_latency_ms
                if deep_outputs is not None:
                    deep_outputs[q.id] = deep_retrieve(engine, q.query_text, top_k=config.TOP_K)

        res = Evaluator.evaluate_engine(
            engine_name=engine_name,
            attack_type=attack_type,
            queries=queries,
            retrieval_outputs=retrieval_outputs,
            retrieval_latencies=retrieval_latencies,
            clean_ground_truth_hits=clean_hits,
            isolated_targets=isolated_targets,
            deep_outputs=deep_outputs
        )
        res.isolated_targets = isolated_targets
        return res

    # 3. Phase 1: Baseline Clean Runs
    print("\n[3/5] Phase 1: Measuring Baseline (Clean Uncompromised Corpus)...")
    for name in engines.keys():
        t0 = time.time()
        res = evaluate_scenario(name, "clean_baseline", docs=clean_docs)
        all_results.append(res)
        clean_hits_by_engine[name] = {t.query_id: t.clean_ground_truth_hit for t in res.traces}
        print(f"   [+] {name:<16} | Recall@5: {res.clean_recall_top5:.1%} | MRR: {res.clean_mrr:.2f} | Latency: {res.avg_retrieval_latency_ms:.1f}ms ({time.time()-t0:.1f}s)")

    # 4. Phase 2: Generating Poisoned Corpora for Attack Vectors and Budgets
    print("\n[4/5] Phase 2: Generating Poisoned Corpora for Attack Vectors and Budgets...")
    # (attack type, description, query_echo). The echo arm matters because appending the
    # target question to the payload is PoisonedRAG's *baseline* black-box construction, not
    # an extreme case -- running only query_echo=False silently reports a weakened reference.
    attack_vectors = [
        ("sparse", "BM25 Keyword Stuffing / TF-IDF Saturation", False),
        ("dense", "Dense Semantic Embedding Alignment", False),
        ("dense", "Dense Semantic + Query Echo (PoisonedRAG reference construction)", True),
        ("hybrid", "Hybrid Dual-Constraint Evasion", False),
        ("graph", "Graph Bridge-Node Injection", False),
        ("entity_swap", "Graph Type-Preserving Entity Swap (LogicPoison construction)", False),
        ("blackbox_category", "Black-Box Category Poisoning (true lower bound, no victim identifier)", False),
        ("blackbox", "Black-Box Topic+Entity (historical variant, uses victim identifier)", False)
    ]
    if include_topological:
        attack_vectors.append(("pure_topological", "Pure Topological Graph Poisoning (Topology Isolation)", False))

    def scenario_key(att_type: str, echo: bool, budget: int) -> str:
        return f"{att_type}{'_echo' if echo else ''}_b{budget}"

    poisoned_corpora = {}
    poisoned_payloads = {}
    for att_type, desc, echo in attack_vectors:
        for b in budgets:
            t0 = time.time()
            key = scenario_key(att_type, echo, b)
            if isolated_targets:
                print(f"   [*] Generating Isolated Poison Payloads: {desc} ({att_type}), Budget: {b}...")
                poisoned_payloads[key] = poison_mgr.generate_isolated_poison_payloads(
                    queries, att_type, attack_budget=b, query_echo=echo
                )
                print(f"       Ready ({len(poisoned_payloads[key])} queries mapped, {time.time()-t0:.2f}s)")
            else:
                print(f"   [*] Generating Poisoned Corpus: {desc} ({att_type}), Budget: {b}...")
                poisoned_corpora[key] = poison_mgr.generate_poisoned_corpus(
                    clean_docs, queries, att_type, attack_budget=b, query_echo=echo
                )
                print(f"       Ready ({len(poisoned_corpora[key])} docs, {time.time()-t0:.2f}s)")

    # 5. Phase 3: Executing Full Attack Matrix (Engines x Attacks x Budgets)
    print("\n[5/5] Phase 3: Executing Full Attack Matrix (Scenarios across 4 Engines and 3 Budgets)...")
    for att_type, desc, echo in attack_vectors:
        print(f"\n   =================================================================")
        print(f"   >>> ATTACK VECTOR: {att_type.upper()}{' +ECHO' if echo else ''} ({desc}) <<<")
        print(f"   =================================================================")
        for b in budgets:
            key = scenario_key(att_type, echo, b)
            for engine_name in engines.keys():
                t0 = time.time()
                # Use a specific attack_type string indicating budget for reporting
                run_att_type = key
                if isolated_targets:
                    res = evaluate_scenario(
                        engine_name,
                        run_att_type,
                        poison_payloads=poisoned_payloads[key],
                        clean_hits=clean_hits_by_engine.get(engine_name)
                    )
                else:
                    p_docs = poisoned_corpora[key]
                    res = evaluate_scenario(
                        engine_name,
                        run_att_type,
                        docs=p_docs,
                        clean_hits=clean_hits_by_engine.get(engine_name)
                    )
                all_results.append(res)
                print(f"      [+] {engine_name:<16} vs {key.upper():<26} | poison@1: {res.retrieval_asr_top1:.1%} | cond: {res.retrieval_asr_cond:.1%} | poison@5: {res.retrieval_asr_top5:.1%} | displaced: {res.gt_displacement_rate:.1%} | Recall@5: {res.clean_recall_top5:.1%} ({time.time()-t0:.1f}s)")

    # Flush embedding cache to disk
    dense.flush_cache()

    # Terminal Output & Report Export
    print("\n" + "=" * 80)
    print("BENCHMARK RESULTS SUMMARY:")
    print("=" * 80)
    BenchmarkReporter.print_terminal_results(all_results)

    manifest = build_run_manifest(
        clean_docs, queries, bridge_count, budgets, isolated_targets, query_echo,
        query_set=query_set, log_ties=log_ties
    )
    manifest_path = reports_dir / "run_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] Run manifest saved: {manifest_path}")

    report_path = reports_dir / "rag_poisoning_comparison_report.md"
    BenchmarkReporter.generate_markdown_report(
        all_results,
        report_path,
        corpus_type=corpus_mode,
        corpus_size=len(clean_docs),
        isolated_targets=isolated_targets,
        query_echo=query_echo,
        bridge_count=bridge_count,
        run_manifest=manifest
    )
    print(f"[+] Full Markdown report generated: {report_path}")

    traces_path = reports_dir / "generation_traces.json"
    BenchmarkReporter.save_generation_traces(all_results, traces_path)
    print(f"[+] Retrieval traces saved: {traces_path}")

    json_path = reports_dir / "comparison_benchmark_results.json"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    summary_data = []
    for r in all_results:
        d = dict(r.__dict__)
        d["traces"] = [t.__dict__ for t in r.traces]
        summary_data.append(d)
    json_path.write_text(json.dumps(summary_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Complete JSON benchmark metrics saved: {json_path}")

    total_elapsed = time.time() - start_total_time
    print(f"\nTotal Execution Time: {total_elapsed:.2f}s ({total_elapsed/60:.1f} min)")

    # Methodology gate. The audit checks restate the findings of the methodological review as
    # assertions over the stored results; running them here is what stops a report shipping
    # with a known-failing invariant while the prose still reads as if it held.
    print("\n" + "=" * 80)
    print("METHODOLOGY GATE (scripts/audit_checks.py)")
    print("=" * 80)
    try:
        from scripts.audit_checks import run_audit
        gate_failed = run_audit(reports_dir)
    except Exception as e:  # a broken gate must be loud, not silently skipped
        print(f"[!] Methodology gate could not run: {e}")
        gate_failed = 1
    if gate_failed:
        print(
            "\n[!] Bramka metodologiczna zwrocila FAIL. Raport zostal wygenerowany, ale "
            "przed uzyciem go poza tym repozytorium nalezy albo naprawic wskazane ustalenia, "
            "albo ujawnic je w Sekcji 6."
        )
    return all_results

def main():
    parser = argparse.ArgumentParser(description="CTI RAG Corpus Poisoning Benchmark: Comparing 4 RAG Architectures")
    parser.add_argument("--corpus", choices=["real", "synthetic"], default="real",
                        help="Corpus type: 'real' (authentic 24k CTI STIX 2.1) or 'synthetic'")
    parser.add_argument("--num_cves", type=int, default=24000,
                        help="Target corpus size for real CTI data (default: 24000)")
    parser.add_argument("--queries", type=int, default=150,
                        help="Number of gold benchmark queries (default: 150 = 3 strata x 50)")
    parser.add_argument("--cost-free", action="store_true", default=None,
                        help="No effect; kept so that older commands still run. The benchmark is "
                             "always a 100%% cost-free local retrieval evaluation ($0.00 API cost).")
    parser.add_argument("--query-echo", action="store_true", default=False,
                        help="Enable verbatim query echo in attack payloads (upper-bound stress test; default: False)")
    parser.add_argument("--topological", action="store_true",
                        help="Include PureTopologicalPoisonAttacker in benchmark")
    parser.add_argument("--isolated-targets", action="store_true", default=False,
                        help="Run isolated target evaluation (1 target query per index instance, Recommendation 3)")
    parser.add_argument("--out-dir", type=str, default=None,
                        help="Directory for report/traces/JSON (default: outputs/reports). Use a "
                             "separate directory to keep an earlier run available for diffing.")
    parser.add_argument("--budgets", type=int, nargs="+", default=[1, 2, 3, 5],
                        help="Attack budgets B to evaluate (e.g. 1 3 5; B<=2 sub-saturation, B>=3 saturation stress-test)")
    parser.add_argument("--bridge-count", type=int, default=40,
                        help="Synthetic bridge nodes per query term for the graph and topological "
                             "attacks (default: 40). This is the single free parameter of those "
                             "vectors and it decides the outcome: sweep it with "
                             "scripts/run_bridge_sweep.py rather than reporting one value as an "
                             "architectural property.")
    parser.add_argument("--query-set", choices=list(QUERY_SETS), default="v2",
                        help="Question templates: 'v2' reproduces the archived v2 run; 'v3' rewords "
                             "the CVE exact-match and attribution templates that produced constant "
                             "context slots and drops attribution questions that contain their own "
                             "answer (see src/corpus/real_query_loader.py).")
    parser.add_argument("--log-ties", action="store_true", default=False,
                        help="Record, per query, a deep untimed ranking and the metric bounds over "
                             "complete tie groups (rank 1 and the rank-k boundary), plus the hybrid "
                             "reranker's candidate pool. Point metrics and latencies are unchanged.")

    args = parser.parse_args()

    run_benchmark_matrix(
        corpus_mode=args.corpus,
        num_cves=args.num_cves,
        num_queries=args.queries,
        query_echo=args.query_echo,
        include_topological=args.topological,
        isolated_targets=args.isolated_targets,
        budgets=args.budgets,
        out_dir=Path(args.out_dir) if args.out_dir else None,
        bridge_count=args.bridge_count,
        query_set=args.query_set,
        log_ties=args.log_ties
    )

if __name__ == "__main__":
    main()
