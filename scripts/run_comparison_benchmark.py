import sys
import json
import time
from pathlib import Path
from typing import List, Dict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import config
from src.corpus.dataset import build_cti_knowledge_base, build_gold_benchmark_queries, CTIDocument, GoldQuery
from src.engines.retrievers import BM25Retriever, DenseFAISSRetriever, HybridRerankRetriever, GraphRAGRetriever, BaseRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.llm.openrouter_client import OpenRouterClient
from src.llm.rag_generator import RAGGenerator
from src.evaluation.llm_judge import LLMJudge, JudgeVerdict
from src.evaluation.metrics import Evaluator, EngineBenchmarkResult
from src.visualization.reporter import BenchmarkReporter

def run_benchmark_matrix():
    print("=" * 80)
    print("🚀 STARTING CTI RAG CORPUS POISONING BENCHMARK (RETRIEVAL + OPENROUTER LLM)")
    print("=" * 80)
    print(f"[*] OpenRouter Generator Model: {config.GENERATOR_MODEL}")
    print(f"[*] OpenRouter Judge Model:     {config.JUDGE_MODEL}")
    print(f"[*] Retrieval Top-K:            {config.TOP_K}")

    start_total_time = time.time()

    # 1. Dataset & Queries
    print("\n[1/5] Loading CTI Ground Truth Dataset & Benchmark Queries...")
    clean_docs = build_cti_knowledge_base()
    queries = build_gold_benchmark_queries()
    print(f"   [+] Loaded {len(clean_docs)} clean CTI intelligence documents (CVE, CWE, MITRE ATT&CK, Sigma, APT)")
    print(f"   [+] Configured {len(queries)} Gold Benchmark test inquiries with ground truth annotations")

    # 2. Initialize Models & Clients
    print("\n[2/5] Initializing 4 Retrieval Engines & OpenRouter LLM Clients...")
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

    client = OpenRouterClient()
    generator = RAGGenerator(client=client, model=config.GENERATOR_MODEL)
    judge = LLMJudge(client=client, model=config.JUDGE_MODEL)
    poison_mgr = CorpusPoisonManager()

    all_results: List[EngineBenchmarkResult] = []

    def evaluate_scenario(engine_name: str, attack_type: str, docs: List[CTIDocument]) -> EngineBenchmarkResult:
        engine = engines[engine_name]
        engine.build_index(docs)

        retrieval_outputs = {}
        generated_responses = {}
        judge_verdicts = {}
        retrieval_latencies = {}
        generation_latencies = {}

        for q in queries:
            # Step A: Retrieval
            t_ret0 = time.time()
            results = engine.retrieve(q.query_text, top_k=config.TOP_K)
            ret_latency_ms = (time.time() - t_ret0) * 1000.0

            retrieval_outputs[q.id] = results
            retrieval_latencies[q.id] = ret_latency_ms

            # Step B: LLM Generation
            t_gen0 = time.time()
            resp = generator.generate_response(q.query_text, results)
            gen_latency_ms = (time.time() - t_gen0) * 1000.0

            generated_responses[q.id] = resp
            generation_latencies[q.id] = gen_latency_ms

            # Step C: LLM Judge
            verdict = judge.evaluate_response(
                query_text=q.query_text,
                ground_truth_answer=q.ground_truth_answer,
                target_poison_assertion=q.target_poison_assertion,
                generated_response=resp
            )
            judge_verdicts[q.id] = verdict

        return Evaluator.evaluate_engine_with_llm(
            engine_name=engine_name,
            attack_type=attack_type,
            queries=queries,
            retrieval_outputs=retrieval_outputs,
            generated_responses=generated_responses,
            judge_verdicts=judge_verdicts,
            retrieval_latencies=retrieval_latencies,
            generation_latencies=generation_latencies
        )

    # 3. Phase 1: Baseline Clean Runs
    print("\n[3/5] Phase 1: Measuring Baseline (Clean Uncompromised Corpus)...")
    for name in engines.keys():
        t0 = time.time()
        res = evaluate_scenario(name, "clean_baseline", clean_docs)
        all_results.append(res)
        print(f"   [+] {name:<16} | Recall@5: {res.clean_recall_top5:.1%} | MRR: {res.clean_mrr:.2f} | Gen ASR: {res.generation_asr:.1%} | GT Retained: {res.ground_truth_retention:.1%} ({time.time()-t0:.1f}s)")

    # 4. Phase 2: Targeted Corpus Poisoning Attacks
    print("\n[4/5] Phase 2: Injecting Targeted Corpus Poisoning Attacks...")
    attack_scenarios = [
        ("Sparse-BM25", "sparse", "BM25 Keyword Stuffing / TF-IDF Saturation"),
        ("Dense-FAISS", "dense", "Dense Semantic Embedding Alignment (PoisonedRAG)"),
        ("Hybrid-Reranker", "hybrid", "Hybrid Dual-Constraint Evasion"),
        ("GraphRAG", "graph", "GraphRAG LogicPoison / Relation Swapping")
    ]

    for engine_name, attack_type, desc in attack_scenarios:
        print(f"\n   [*] Executing Attack: {desc} -> Target: {engine_name}")
        poisoned_docs = poison_mgr.generate_poisoned_corpus(clean_docs, queries, attack_type)
        res = evaluate_scenario(engine_name, attack_type, poisoned_docs)
        all_results.append(res)
        print(f"      -> Retr Top-1 ASR: {res.retrieval_asr_top1:.1%} | Retr Top-5 ASR: {res.retrieval_asr_top5:.1%} | LLM Gen ASR: {res.generation_asr:.1%} | GT Retained: {res.ground_truth_retention:.1%}")

    # 5. Phase 3: Cross-Attack Robustness on Hybrid-Reranker
    print("\n[5/5] Phase 3: Cross-Attack Evaluation on Hybrid-Reranker...")
    for attack_type in ["sparse", "dense", "graph"]:
        poisoned_docs = poison_mgr.generate_poisoned_corpus(clean_docs, queries, attack_type)
        res = evaluate_scenario("Hybrid-Reranker", f"cross_{attack_type}", poisoned_docs)
        all_results.append(res)
        print(f"   [+] Hybrid vs CROSS_{attack_type.upper():<6} | Retr ASR@1: {res.retrieval_asr_top1:.1%} | LLM Gen ASR: {res.generation_asr:.1%} | GT Retained: {res.ground_truth_retention:.1%}")

    # Terminal Output & Report Export
    print("\n" + "=" * 80)
    print("📊 BENCHMARK RESULTS SUMMARY:")
    print("=" * 80)
    BenchmarkReporter.print_terminal_results(all_results)

    report_path = config.REPORTS_DIR / "rag_poisoning_comparison_report.md"
    BenchmarkReporter.generate_markdown_report(all_results, report_path)
    print(f"\n[+] Full Markdown report generated: {report_path}")

    traces_path = config.REPORTS_DIR / "generation_traces.json"
    BenchmarkReporter.save_generation_traces(all_results, traces_path)
    print(f"[+] LLM Generation & Judge traces saved: {traces_path}")

    json_path = config.REPORTS_DIR / "comparison_benchmark_results.json"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    summary_data = []
    for r in all_results:
        d = dict(r.__dict__)
        d["traces"] = [t.__dict__ for t in r.traces]
        summary_data.append(d)
    json_path.write_text(json.dumps(summary_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Complete JSON benchmark metrics saved: {json_path}")

    print(f"\n⏱️ Total Execution Time: {time.time() - start_total_time:.2f}s")
    return all_results

if __name__ == "__main__":
    run_benchmark_matrix()
