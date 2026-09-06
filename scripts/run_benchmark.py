import sys
import json
import time
from pathlib import Path
from typing import List, Dict

PROJECT_ROOT = Path("/home/mpysiek/rag_poisoning_benchmark")
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import config
from src.corpus.dataset import build_cti_knowledge_base, build_gold_benchmark_queries, CTIDocument, GoldQuery
from src.engines.retrievers import BM25Retriever, DenseFAISSRetriever, HybridRerankRetriever, GraphRAGRetriever, BaseRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.evaluation.metrics import Evaluator, EngineBenchmarkResult
from src.visualization.reporter import BenchmarkReporter

def run_experiment() -> List[EngineBenchmarkResult]:
    print("[1/4] Inicjalizacja korpusu CTI i zestawu zapytan Gold Benchmark...")
    clean_docs = build_cti_knowledge_base()
    queries = build_gold_benchmark_queries()
    print(f"   [+] Zaladowano {len(clean_docs)} dokumentow CTI (MITRE ATT&CK, CVE, CWE, Sigma)")
    print(f"   [+] Skonfigurowano {len(queries)} zapytan testowych ze zlotym standardem (Ground Truth)")

    print("\n[2/4] Budowanie 4 wyizolowanych silnikow wyszukiwania...")
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

    poison_mgr = CorpusPoisonManager()
    all_results: List[EngineBenchmarkResult] = []

    # Phase 1: Baseline
    print("\n[3/4] Faza 1: Pomiary Baseline (Nieskazona baza wiedzy)...")
    for name, engine in engines.items():
        engine.build_index(clean_docs)
        outputs = {}
        for q in queries:
            outputs[q.id] = engine.retrieve(q.query_text, top_k=config.TOP_K)
        res = Evaluator.evaluate_engine(name, "clean_baseline", queries, outputs)
        all_results.append(res)
        print(f"   [+] {name:<16} | Recall@5: {res.clean_recall_top5:.1%} | MRR: {res.clean_mrr:.2f} | ASR: {res.end_to_end_asr:.1%}")

    # Phase 2: Targeted Corpus Poisoning Attacks
    print("\n[4/4] Faza 2: Generowanie i wstrzykiwanie atakow Corpus Poisoning...")
    attack_scenarios = [
        ("Sparse-BM25", "sparse", "BM25 Keyword Stuffing / TF-IDF Saturation"),
        ("Dense-FAISS", "dense", "Dense Semantic Embedding Alignment"),
        ("Hybrid-Reranker", "hybrid", "Hybrid Dual-Constraint Evasion"),
        ("GraphRAG", "graph", "GraphRAG LogicPoison / Relation Swapping")
    ]

    for engine_name, attack_type, desc in attack_scenarios:
        print(f"\n   [*] Symulacja ataku: {desc} (Cel: {engine_name})")
        poisoned_docs = poison_mgr.generate_poisoned_corpus(clean_docs, queries, attack_type)
        engine = engines[engine_name]
        engine.build_index(poisoned_docs)

        outputs = {}
        for q in queries:
            outputs[q.id] = engine.retrieve(q.query_text, top_k=config.TOP_K)

        res = Evaluator.evaluate_engine(engine_name, attack_type, queries, outputs)
        all_results.append(res)
        print(f"      -> Top-1 Hijack: {res.retrieval_asr_top1:.1%} | Top-5 ASR: {res.retrieval_asr_top5:.1%} | End-to-End ASR: {res.end_to_end_asr:.1%}")

    # Cross-test: Test Hybrid Reranker under all attack vectors
    print("\n[*] Walidacja odpornosci Hybrid-Reranker przeciwko pozostalym wektorom atakow...")
    for attack_type in ["sparse", "dense", "graph"]:
        poisoned_docs = poison_mgr.generate_poisoned_corpus(clean_docs, queries, attack_type)
        hybrid.build_index(poisoned_docs)
        outputs = {q.id: hybrid.retrieve(q.query_text, top_k=config.TOP_K) for q in queries}
        res = Evaluator.evaluate_engine("Hybrid-Reranker", f"cross_{attack_type}", queries, outputs)
        all_results.append(res)

    print("\n" + "="*80)
    print("PODSUMOWANIE METRYK I WYNIKOW BENCHMARKU:")
    print("="*80)
    BenchmarkReporter.print_terminal_results(all_results)

    report_path = config.REPORTS_DIR / "rag_poisoning_report.md"
    BenchmarkReporter.generate_markdown_report(all_results, report_path)
    print(f"\n[+] Pelny raport Markdown zapisany: {report_path}")

    json_path = config.REPORTS_DIR / "benchmark_results.json"
    json_data = [r.__dict__ for r in all_results]
    json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
    print(f"[+] Surowe wyniki JSON zapisane: {json_path}")

    return all_results

if __name__ == "__main__":
    run_experiment()
