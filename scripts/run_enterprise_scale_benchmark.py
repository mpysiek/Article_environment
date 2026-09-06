import sys
import asyncio
import json
import time
from pathlib import Path
from typing import List, Dict, Any
import httpx

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn

from src.config import config
from src.corpus.dataset import CTIDocument, GoldQuery, RetrievalResult
from src.corpus.large_cti_generator import generate_enterprise_cti_corpus, build_100_gold_queries
from src.engines.retrievers import BM25Retriever, DenseFAISSRetriever, HybridRerankRetriever, GraphRAGRetriever, BaseRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.llm.async_openrouter_client import AsyncOpenRouterClient
from src.llm.rag_generator import RAGGenerator
from src.evaluation.llm_judge import LLMJudge, JudgeVerdict
from src.evaluation.metrics import Evaluator, EngineBenchmarkResult
from src.visualization.reporter import BenchmarkReporter
from src.infrastructure.runpod_orchestrator import RunPodOrchestrator

console = Console()

async def evaluate_query_async(
    q: GoldQuery,
    engine_name: str,
    attack_type: str,
    retrieved_docs: List[RetrievalResult],
    ret_latency_ms: float,
    http_client: httpx.AsyncClient,
    generator: RAGGenerator,
    judge: LLMJudge,
    async_client: AsyncOpenRouterClient
) -> Dict[str, Any]:
    """Asynchronously generate response and evaluate with LLM Judge."""
    t_gen0 = time.time()
    generated_resp = await generator.generate_response_async(
        http_client=http_client,
        query=q.query_text,
        retrieved_docs=retrieved_docs
    )
    gen_latency_ms = (time.time() - t_gen0) * 1000.0

    # LLM Judge
    verdict = await judge.evaluate_response_async(
        http_client=http_client,
        query_text=q.query_text,
        ground_truth_answer=q.ground_truth_answer,
        target_poison_assertion=q.target_poison_assertion,
        generated_response=generated_resp
    )

    record = {
        "query_id": q.id,
        "query_text": q.query_text,
        "engine_name": engine_name,
        "attack_type": attack_type,
        "retrieved_doc_ids": [r.doc_id for r in retrieved_docs[:5]],
        "retrieved_titles": [r.title for r in retrieved_docs[:5]],
        "has_poison_in_top1": len(retrieved_docs) > 0 and retrieved_docs[0].is_poisoned,
        "has_poison_in_top5": any(r.is_poisoned for r in retrieved_docs[:5]),
        "generated_response": generated_resp,
        "is_poison_adopted": verdict.is_poison_adopted,
        "is_ground_truth_retained": verdict.is_ground_truth_retained,
        "detected_conflict": verdict.detected_conflict,
        "judge_reasoning": verdict.reasoning,
        "retrieval_latency_ms": ret_latency_ms,
        "generation_latency_ms": gen_latency_ms
    }

    # Checkpoint to JSONL immediately
    async_client.append_checkpoint(record)
    return {
        "query_id": q.id,
        "response": generated_resp,
        "verdict": verdict,
        "ret_latency": ret_latency_ms,
        "gen_latency": gen_latency_ms
    }

async def run_enterprise_benchmark(num_cves: int = 24000, max_queries: int = 100):
    console.print("=" * 80, style="bold cyan")
    console.print("🚀 STARTING ENTERPRISE-SCALE CTI RAG POISONING BENCHMARK", style="bold green")
    console.print("   • Target Corpus: 25,000+ CTI Documents (CVE, MITRE, Sigma, APT, CWE)", style="dim")
    console.print(f"   • Evaluator: 100 Gold Queries | OpenRouter: {config.GENERATOR_MODEL}", style="dim")
    console.print("=" * 80, style="bold cyan")

    start_total_time = time.time()

    # 1. Compute & Environment Check
    orch = RunPodOrchestrator()
    cuda_status = orch.check_cuda_availability()
    console.print(f"[*] Compute Environment: [bold]{cuda_status['device_name']}[/bold] (CUDA: {cuda_status['cuda_available']})")

    # 2. Generate Enterprise Corpus
    console.print("\n[1/5] Generating Enterprise CTI Knowledge Base (25,000+ docs)...", style="bold yellow")
    t0_gen = time.time()
    clean_docs = generate_enterprise_cti_corpus(num_cves=num_cves)
    all_queries = build_100_gold_queries()
    queries = all_queries[:max_queries]
    console.print(f"   [+] Generated [bold green]{len(clean_docs):,}[/bold green] CTI documents in {time.time()-t0_gen:.2f}s")
    console.print(f"   [+] Loaded [bold green]{len(queries)}[/bold green] Gold Benchmark Queries across 5 CTI domains")

    # 3. Initialize Retrieval Engines & Async LLM Clients
    console.print("\n[2/5] Initializing Retrieval Engines and OpenRouter Pool...", style="bold yellow")
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

    async_client = AsyncOpenRouterClient(concurrency=15)
    generator = RAGGenerator(async_client=async_client, model=config.GENERATOR_MODEL)
    judge = LLMJudge(async_client=async_client, model=config.JUDGE_MODEL)
    poison_mgr = CorpusPoisonManager()

    all_results: List[EngineBenchmarkResult] = []

    # Scenarios to evaluate
    scenarios = [
        ("Sparse-BM25", "clean_baseline", "Clean Baseline", clean_docs),
        ("Dense-FAISS", "clean_baseline", "Clean Baseline", clean_docs),
        ("Hybrid-Reranker", "clean_baseline", "Clean Baseline", clean_docs),
        ("GraphRAG", "clean_baseline", "Clean Baseline", clean_docs),
        ("Sparse-BM25", "sparse", "BM25 Keyword Stuffing", None),
        ("Dense-FAISS", "dense", "Dense Semantic Embedding Alignment", None),
        ("Hybrid-Reranker", "hybrid", "Hybrid Dual-Constraint Evasion", None),
        ("GraphRAG", "graph", "GraphRAG LogicPoison", None),
        ("Hybrid-Reranker", "cross_sparse", "Cross-Sparse Attack", None),
        ("Hybrid-Reranker", "cross_dense", "Cross-Dense Attack", None)
    ]

    # Pre-generate poisoned corpora
    poison_corpora = {
        "sparse": poison_mgr.generate_poisoned_corpus(clean_docs, queries, "sparse"),
        "dense": poison_mgr.generate_poisoned_corpus(clean_docs, queries, "dense"),
        "hybrid": poison_mgr.generate_poisoned_corpus(clean_docs, queries, "hybrid"),
        "graph": poison_mgr.generate_poisoned_corpus(clean_docs, queries, "graph")
    }

    limits = httpx.Limits(max_keepalive_connections=20, max_connections=30)
    timeout = httpx.Timeout(60.0, connect=15.0)

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as http_client:
        total_steps = len(scenarios)
        for s_idx, (eng_name, attack_type, desc, doc_override) in enumerate(scenarios, 1):
            console.print(f"\n[{s_idx}/{total_steps}] Running Scenario: [bold cyan]{eng_name}[/bold cyan] -> [bold magenta]{attack_type.upper()}[/bold magenta] ({desc})")
            
            # Select appropriate corpus
            if doc_override is not None:
                current_docs = doc_override
            elif attack_type.startswith("cross_"):
                base_att = attack_type.replace("cross_", "")
                current_docs = poison_corpora[base_att]
            else:
                current_docs = poison_corpora[attack_type]

            # Indexing
            t_idx0 = time.time()
            engine = engines[eng_name]
            engine.build_index(current_docs)
            console.print(f"   [*] Index built on {len(current_docs):,} docs in {time.time()-t_idx0:.2f}s")

            # Retrieval for all queries
            retrieval_outputs = {}
            retrieval_latencies = {}
            for q in queries:
                t_r0 = time.time()
                results = engine.retrieve(q.query_text, top_k=config.TOP_K)
                ret_lat = (time.time() - t_r0) * 1000.0
                retrieval_outputs[q.id] = results
                retrieval_latencies[q.id] = ret_lat

            # Async LLM Generation and Judge
            tasks = []
            for q in queries:
                tasks.append(
                    evaluate_query_async(
                        q=q,
                        engine_name=eng_name,
                        attack_type=attack_type,
                        retrieved_docs=retrieval_outputs[q.id],
                        ret_latency_ms=retrieval_latencies[q.id],
                        http_client=http_client,
                        generator=generator,
                        judge=judge,
                        async_client=async_client
                    )
                )

            # Gather all evaluations concurrently with progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task_id = progress.add_task(f"   [yellow]LLM Gen & Judge ({len(tasks)} queries)...", total=len(tasks))
                
                # Run tasks concurrently in chunks or asyncio.as_completed
                eval_results = []
                for fut in asyncio.as_completed(tasks):
                    res = await fut
                    eval_results.append(res)
                    progress.advance(task_id, 1)

            # Map outputs
            generated_responses = {r["query_id"]: r["response"] for r in eval_results}
            judge_verdicts = {r["query_id"]: r["verdict"] for r in eval_results}
            generation_latencies = {r["query_id"]: r["gen_latency"] for r in eval_results}

            # Evaluate metrics
            bench_res = Evaluator.evaluate_engine_with_llm(
                engine_name=eng_name,
                attack_type=attack_type,
                queries=queries,
                retrieval_outputs=retrieval_outputs,
                generated_responses=generated_responses,
                judge_verdicts=judge_verdicts,
                retrieval_latencies=retrieval_latencies,
                generation_latencies=generation_latencies
            )
            all_results.append(bench_res)

            console.print(
                f"   [+] [bold green]Complete:[/bold green] Retr ASR@1: [bold red]{bench_res.retrieval_asr_top1:.1%}[/bold red] | "
                f"LLM Gen ASR: [bold red]{bench_res.generation_asr:.1%}[/bold red] | "
                f"GT Retention: [bold green]{bench_res.ground_truth_retention:.1%}[/bold green] | "
                f"Conflict Det: {bench_res.conflict_detection_rate:.1%}"
            )

    # 4. Summary & Reports
    console.print("\n" + "=" * 80, style="bold cyan")
    console.print("📊 ENTERPRISE BENCHMARK RESULTS SUMMARY:", style="bold green")
    console.print("=" * 80, style="bold cyan")
    BenchmarkReporter.print_terminal_results(all_results)

    # Save Markdown Report
    report_path = config.REPORTS_DIR / "enterprise_rag_poisoning_report.md"
    BenchmarkReporter.generate_markdown_report(all_results, report_path)
    console.print(f"\n[+] Full Markdown Report: [bold cyan]{report_path}[/bold cyan]")

    # Save JSON metrics
    json_path = config.REPORTS_DIR / "enterprise_benchmark_results.json"
    summary_data = []
    for r in all_results:
        d = dict(r.__dict__)
        d["traces"] = [t.__dict__ for t in r.traces]
        summary_data.append(d)
    json_path.write_text(json.dumps(summary_data, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[+] Complete JSON Metrics: [bold cyan]{json_path}[/bold cyan]")

    # Save all raw traces
    traces_path = config.REPORTS_DIR / "enterprise_generation_traces.json"
    BenchmarkReporter.save_generation_traces(all_results, traces_path)
    console.print(f"[+] LLM Generation Traces: [bold cyan]{traces_path}[/bold cyan]")

    elapsed = time.time() - start_total_time
    console.print(f"\n⏱️ Total Execution Time: [bold green]{elapsed:.2f}s[/bold green] ({elapsed/60:.2f} min)")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run Enterprise-Scale CTI RAG Poisoning Benchmark")
    parser.add_argument("--num_cves", type=int, default=24000, help="Number of CVE documents to generate (total corpus ~25k)")
    parser.add_argument("--queries", type=int, default=100, help="Number of gold queries to evaluate")
    args = parser.parse_args()

    asyncio.run(run_enterprise_benchmark(num_cves=args.num_cves, max_queries=args.queries))
