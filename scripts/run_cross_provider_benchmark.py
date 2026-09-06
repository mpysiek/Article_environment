#!/usr/bin/env python3
import argparse
import asyncio
import json
import time
import copy
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from typing import Dict, List, Any
import httpx
from dataclasses import asdict

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

from src.config import config, CROSS_PROVIDER_TIERS
from src.corpus.real_cti_loader import RealCTILoader
from src.corpus.real_query_loader import build_100_real_gold_queries
from src.corpus.large_cti_generator import generate_enterprise_cti_corpus, build_100_gold_queries
from src.engines.retrievers import BM25Retriever, DenseFAISSRetriever, HybridRerankRetriever, GraphRAGRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.llm.async_openrouter_client import AsyncOpenRouterClient
from src.llm.rag_generator import RAGGenerator
from src.evaluation.llm_judge import LLMJudge, JudgeVerdict
from src.evaluation.metrics import Evaluator, EngineBenchmarkResult, GenerationTrace

async def run_scenario(
    scenario_name: str,
    attack_type: str,
    engine: Any,
    corpus: list,
    queries: list,
    generator: RAGGenerator,
    judge: LLMJudge,
    http_client: httpx.AsyncClient,
    progress: Progress,
    task_id: Any
) -> EngineBenchmarkResult:
    
    # 1. Build Index
    progress.update(task_id, description=f"[cyan]{scenario_name}: Building index...")
    engine.build_index(corpus)

    retrieval_outputs = {}
    generated_responses = {}
    judge_verdicts = {}
    retrieval_latencies = {}
    generation_latencies = {}

    progress.update(task_id, description=f"[cyan]{scenario_name}: Retrieving...")
    for q in queries:
        t_r0 = time.time()
        retrieval_outputs[q.id] = engine.retrieve(q.query_text)
        retrieval_latencies[q.id] = (time.time() - t_r0) * 1000.0  # ms

    progress.update(task_id, description=f"[cyan]{scenario_name}: Generating & Judging...")
    
    async def process_query(q):
        t_g0 = time.time()
        resp = await generator.generate_response_async(http_client, q.query_text, retrieval_outputs[q.id])
        latency = (time.time() - t_g0) * 1000.0
        
        verdict = await judge.evaluate_response_async(
            http_client,
            q.query_text,
            q.ground_truth_answer,
            q.target_poison_assertion,
            resp
        )
        return q.id, resp, latency, verdict

    tasks = [process_query(q) for q in queries]
    
    completed = 0
    total = len(queries)
    for f in asyncio.as_completed(tasks):
        q_id, resp, latency, verdict = await f
        generated_responses[q_id] = resp
        generation_latencies[q_id] = latency
        judge_verdicts[q_id] = verdict
        completed += 1
        progress.update(task_id, description=f"[cyan]{scenario_name}: LLM {completed}/{total}...")

    progress.update(task_id, description=f"[green]{scenario_name}: Done!")
    progress.advance(task_id, 1)

    return Evaluator.evaluate_engine_with_llm(
        engine_name=engine.name,
        attack_type=attack_type,
        queries=queries,
        retrieval_outputs=retrieval_outputs,
        generated_responses=generated_responses,
        judge_verdicts=judge_verdicts,
        retrieval_latencies=retrieval_latencies,
        generation_latencies=generation_latencies
    )

async def main():
    parser = argparse.ArgumentParser(description="Cross-Provider RAG Poisoning Benchmark")
    parser.add_argument("--tier", choices=['mid', 'low', 'baseline'], default='mid')
    parser.add_argument("--corpus_mode", choices=['real', 'synthetic'], default='real')
    parser.add_argument("--num_cves", type=int, default=24000)
    parser.add_argument("--queries", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=15)
    args = parser.parse_args()

    console = Console()
    console.print(f"[bold blue]Starting Cross-Provider Benchmark ({args.tier} tier)[/bold blue]")

    tier_info = CROSS_PROVIDER_TIERS[args.tier]
    
    console.print("[yellow]Loading corpus...[/yellow]")
    if args.corpus_mode == 'real':
        clean_corpus = RealCTILoader().load_full_real_corpus(target_cves=args.num_cves)
        queries = build_100_real_gold_queries()[:args.queries]
    else:
        clean_corpus = generate_enterprise_cti_corpus(num_cves=args.num_cves)
        queries = build_100_gold_queries()[:args.queries]

    console.print(f"Loaded {len(clean_corpus)} documents and {len(queries)} queries.")

    console.print("[yellow]Generating poisoned corpora...[/yellow]")
    poison_manager = CorpusPoisonManager()
    corpora = {
        "clean": clean_corpus,
        "sparse": poison_manager.generate_poisoned_corpus(clean_corpus, queries, "sparse"),
        "dense": poison_manager.generate_poisoned_corpus(clean_corpus, queries, "dense"),
        "hybrid": poison_manager.generate_poisoned_corpus(clean_corpus, queries, "hybrid"),
        "graph": poison_manager.generate_poisoned_corpus(clean_corpus, queries, "graph")
    }

    bm25 = BM25Retriever()
    dense = DenseFAISSRetriever()
    hybrid = HybridRerankRetriever(bm25, dense)
    graph = GraphRAGRetriever()

    async_client = AsyncOpenRouterClient(concurrency=args.concurrency)
    generator = RAGGenerator(async_client=async_client, model=tier_info['generator_model'])
    judge = LLMJudge(async_client=async_client, model=tier_info['judge_model'])

    scenarios = [
        ("Baseline Sparse", "clean", bm25, corpora["clean"]),
        ("Baseline Dense", "clean", dense, corpora["clean"]),
        ("Baseline Hybrid", "clean", hybrid, corpora["clean"]),
        ("Baseline Graph", "clean", graph, corpora["clean"]),
        
        ("Poisoned Sparse", "sparse", bm25, corpora["sparse"]),
        ("Poisoned Dense", "dense", dense, corpora["dense"]),
        ("Poisoned Hybrid", "hybrid", hybrid, corpora["hybrid"]),
        ("Poisoned Graph", "graph", graph, corpora["graph"]),
        
        ("Cross Sparse (Hybrid)", "cross_sparse", hybrid, corpora["sparse"]),
        ("Cross Dense (Hybrid)", "cross_dense", hybrid, corpora["dense"])
    ]

    results = []
    all_traces = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
        overall_task = progress.add_task("[bold magenta]Running scenarios...", total=len(scenarios))
        
        async with httpx.AsyncClient(timeout=120.0) as http_client:
            for name, attack_type, engine, corpus in scenarios:
                task_id = progress.add_task(f"[cyan]Initializing {name}...", total=1)
                res = await run_scenario(name, attack_type, engine, corpus, queries, generator, judge, http_client, progress, task_id)
                results.append(res)
                all_traces.extend(res.traces)
                progress.advance(overall_task, 1)

    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    md_path = config.REPORTS_DIR / "cross_provider_rag_poisoning_report.md"
    from src.visualization.reporter import BenchmarkReporter
    BenchmarkReporter.generate_markdown_report(results, md_path)

    json_results = [
        {
            "engine": r.engine_name,
            "attack_type": r.attack_type,
            "retrieval_asr_top5": r.retrieval_asr_top5,
            "generation_asr": r.generation_asr,
            "gt_retention": r.ground_truth_retention,
            "conflict_detection": r.conflict_detection_rate,
            "avg_retrieval_latency_ms": r.avg_retrieval_latency_ms,
            "avg_generation_latency_ms": r.avg_generation_latency_ms,
            "total_queries": r.total_queries
        } for r in results
    ]
    with open(config.REPORTS_DIR / "cross_provider_benchmark_results.json", "w") as f:
        json.dump(json_results, f, indent=2)

    with open(config.REPORTS_DIR / "cross_provider_generation_traces.json", "w") as f:
        json.dump([asdict(t) for t in all_traces], f, indent=2)

    console.print("\n[bold]Benchmark Summary & Statistical Significance[/bold]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Engine")
    table.add_column("Attack Type")
    table.add_column("Retrieval ASR@5", justify="right")
    table.add_column("Generation ASR", justify="right")
    table.add_column("GT Retention", justify="right")

    for r in results:
        table.add_row(
            r.engine_name,
            r.attack_type,
            f"{r.retrieval_asr_top5:.1%}",
            f"{r.generation_asr:.1%}",
            f"{r.ground_truth_retention:.1%}"
        )
    console.print(table)

if __name__ == "__main__":
    asyncio.run(main())
