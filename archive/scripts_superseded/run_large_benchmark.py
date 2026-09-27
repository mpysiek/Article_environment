import sys
import json
import time
from pathlib import Path
from typing import List, Dict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import config
from src.corpus.large_cti_generator import generate_enterprise_cti_corpus, build_100_gold_queries
from src.engines.retrievers import BM25Retriever, DenseFAISSRetriever, HybridRerankRetriever, GraphRAGRetriever, BaseRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.evaluation.metrics import Evaluator, EngineBenchmarkResult
from src.visualization.reporter import BenchmarkReporter

def run_large_experiment():
    print("=" * 80)
    print("🔥 ROZPOCZYNAM EKSPERYMENT NA DUŻYM KORPUSIE CTI (Large-Scale Corpus Poisoning)")
    print("=" * 80)

    start_time = time.time()
    clean_docs = generate_enterprise_cti_corpus(num_cves=500)
    queries = build_100_gold_queries()

    print(f"\n[1/4] Wygenerowano duży korpus CTI:")
    print(f"   • Liczba dokumentów w bazie: {len(clean_docs)}")
    print(f"   • Złote zapytania testowe: {len(queries)}")

    print("\n[2/4] Inicjalizacja i budowa indeksów 4 silników RAG...")
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

    # Phase 1: Baseline Clean Corpus
    print("\n[3/4] Faza 1: Pomiary Baseline na dużym korpusie...")
    for name, engine in engines.items():
        t0 = time.time()
        engine.build_index(clean_docs)
        outputs = {q.id: engine.retrieve(q.query_text, top_k=config.TOP_K) for q in queries}
        res = Evaluator.evaluate_engine(name, "clean_baseline", queries, outputs)
        all_results.append(res)
        print(f"   [+] {name:<16} | Recall@5: {res.clean_recall_top5:.1%} | MRR: {res.clean_mrr:.2f} | Czas: {time.time()-t0:.2f}s")

    # Phase 2: Targeted Corpus Poisoning Attacks
    print("\n[4/4] Faza 2: Wstrzykiwanie ataków Corpus Poisoning i ocena ASR...")
    attack_scenarios = [
        ("Sparse-BM25", "sparse", "BM25 Keyword Stuffing / Frequency Saturation"),
        ("Dense-FAISS", "dense", "Dense Semantic Embedding Alignment"),
        ("Hybrid-Reranker", "hybrid", "Hybrid Dual-Constraint Evasion"),
        ("GraphRAG", "graph", "GraphRAG LogicPoison / Relation Swapping")
    ]

    for engine_name, attack_type, desc in attack_scenarios:
        print(f"\n   [*] Symulacja ataku: {desc} (Cel: {engine_name})")
        poisoned_docs = poison_mgr.generate_poisoned_corpus(clean_docs, queries, attack_type)
        engine = engines[engine_name]
        engine.build_index(poisoned_docs)

        outputs = {q.id: engine.retrieve(q.query_text, top_k=config.TOP_K) for q in queries}
        res = Evaluator.evaluate_engine(engine_name, attack_type, queries, outputs)
        all_results.append(res)
        print(f"      -> Top-1 Hijack ASR: {res.retrieval_asr_top1:.1%} | Top-5 ASR: {res.retrieval_asr_top5:.1%}")

    # Cross-evaluation on Hybrid
    print("\n[*] Walidacja odporności Hybrid-Reranker na ataki krzyżowe...")
    for attack_type in ["sparse", "dense", "graph"]:
        poisoned_docs = poison_mgr.generate_poisoned_corpus(clean_docs, queries, attack_type)
        hybrid.build_index(poisoned_docs)
        outputs = {q.id: hybrid.retrieve(q.query_text, top_k=config.TOP_K) for q in queries}
        res = Evaluator.evaluate_engine("Hybrid-Reranker", f"cross_{attack_type}", queries, outputs)
        all_results.append(res)

    print("\n" + "="*80)
    print("📊 PODSUMOWANIE WYNIKÓW EKSPERYMENTU NA DUŻYM KORPUSIE:")
    print("="*80)
    BenchmarkReporter.print_terminal_results(all_results)

    report_path = config.REPORTS_DIR / "large_scale_rag_poisoning_report.md"
    BenchmarkReporter.generate_markdown_report(all_results, report_path)
    print(f"\n[+] Raport Markdown zapisany w: {report_path}")

    json_path = config.REPORTS_DIR / "large_benchmark_results.json"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_data = [r.__dict__ for r in all_results]
    json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
    print(f"[+] Dane JSON zapisane w: {json_path}")
    print(f"\n⏱️ Całkowity czas wykonania: {time.time()-start_time:.2f}s")

if __name__ == "__main__":
    run_large_experiment()
