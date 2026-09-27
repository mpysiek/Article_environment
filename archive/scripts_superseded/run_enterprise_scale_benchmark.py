#!/usr/bin/env python3
"""Enterprise-scale CTI RAG poisoning benchmark, split into three stages.

Same A/B/C pipeline as run_cross_provider_benchmark.py -- see src/evaluation/stages.py --
differing only in the corpus (synthetic enterprise generator) and the scenario matrix,
which pairs each engine with its matched attack plus two cross-attacks on Hybrid.

    A  retrieve + generate     synchronous, minutes
    B  judge                   OpenRouter Batch API (~50% cheaper), up to 24h
    C  join + evaluate         local, seconds

  python scripts/run_enterprise_scale_benchmark.py --queries 100
  python scripts/run_enterprise_scale_benchmark.py --queries 100 --stage a
  python scripts/run_enterprise_scale_benchmark.py --stage b --run-id <id> [--resume-batch]
  python scripts/run_enterprise_scale_benchmark.py --stage c --run-id <id>
"""
import argparse
import asyncio
import json
import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from typing import Dict, List, Any

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from src.config import config
from src.corpus.large_cti_generator import generate_enterprise_cti_corpus, build_100_gold_queries
from src.engines.retrievers import (BM25Retriever, DenseFAISSRetriever,
                                    HybridRerankRetriever, GraphRAGRetriever, BaseRetriever)
from src.attacks.poisoning import CorpusPoisonManager
from src.llm.async_openrouter_client import AsyncOpenRouterClient
from src.llm.batch_client import OpenRouterBatchClient
from src.llm.rag_generator import RAGGenerator
from src.evaluation.llm_judge import LLMJudge, JudgeVerdict
from src.evaluation.metrics import Evaluator, EngineBenchmarkResult
from src.evaluation import stages
from src.visualization.reporter import BenchmarkReporter

console = Console()
BATCH_ENDPOINT = "/v1/chat/completions"


def build_scenarios(clean_docs, poison_corpora):
    """(scenario label, engine key, attack type, corpus) for each measured configuration."""
    def corpus_for(attack):
        if attack == "clean_baseline":
            return clean_docs
        return poison_corpora[attack.replace("cross_", "")]

    raw = [
        ("Sparse-BM25", "clean_baseline"),
        ("Dense-FAISS", "clean_baseline"),
        ("Hybrid-Reranker", "clean_baseline"),
        ("GraphRAG", "clean_baseline"),
        ("Sparse-BM25", "sparse"),
        ("Dense-FAISS", "dense"),
        ("Hybrid-Reranker", "hybrid"),
        ("GraphRAG", "graph"),
        ("Hybrid-Reranker", "cross_sparse"),
        ("Hybrid-Reranker", "cross_dense"),
    ]
    return [(f"{eng} / {att}", eng, att, corpus_for(att)) for eng, att in raw]


# ------------------------------------------------------------------ stage A

async def stage_a(args, run_id) -> Path:
    t_start = time.time()
    console.print("\n[1/3] Generating Enterprise CTI Knowledge Base...", style="bold yellow")
    clean_docs = generate_enterprise_cti_corpus(num_cves=args.num_cves)
    all_queries = build_100_gold_queries()
    if args.queries > len(all_queries):
        raise ValueError(
            f"The synthetic gold query set has {len(all_queries)} queries but --queries "
            f"{args.queries} was requested. Use run_cross_provider_benchmark.py "
            f"--corpus_mode real for larger runs."
        )
    queries = all_queries[:args.queries]
    console.print(f"   [+] {len(clean_docs):,} documents | {len(queries)} gold queries")

    console.print("\n[2/3] Building engines and poisoned corpora...", style="bold yellow")
    bm25 = BM25Retriever()
    dense = DenseFAISSRetriever(model_name=config.DENSE_MODEL_NAME)
    hybrid = HybridRerankRetriever(bm25, dense, reranker_name=config.RERANKER_MODEL_NAME)
    graph = GraphRAGRetriever()
    engines: Dict[str, BaseRetriever] = {
        "Sparse-BM25": bm25, "Dense-FAISS": dense,
        "Hybrid-Reranker": hybrid, "GraphRAG": graph,
    }

    poison_mgr = CorpusPoisonManager()
    poison_corpora = {
        attack: poison_mgr.generate_poisoned_corpus(clean_docs, queries, attack)
        for attack in ("sparse", "dense", "hybrid", "graph")
    }

    scenarios = build_scenarios(clean_docs, poison_corpora)
    async_client = AsyncOpenRouterClient(concurrency=args.concurrency)
    generator = RAGGenerator(async_client=async_client, model=config.GENERATOR_MODEL)

    console.print("\n[3/3] Retrieval + generation...", style="bold yellow")
    all_records: List[Dict[str, Any]] = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TimeElapsedColumn(), console=console) as progress:
        overall = progress.add_task("[bold magenta]Stage A", total=len(scenarios))
        async with httpx.AsyncClient(timeout=120.0) as http_client:
            for label, eng_name, attack_type, corpus in scenarios:
                engine = engines[eng_name]
                progress.update(overall, description=f"[cyan]{label}: indexing")
                engine.build_index(corpus)

                retrieved, ret_lat = {}, {}
                for q in queries:
                    t0 = time.time()
                    retrieved[q.id] = engine.retrieve(q.query_text, top_k=config.TOP_K)
                    ret_lat[q.id] = (time.time() - t0) * 1000.0

                async def one(q):
                    t0 = time.time()
                    resp = await generator.generate_response_async(
                        http_client, q.query_text, retrieved[q.id])
                    return q, resp, (time.time() - t0) * 1000.0

                done = 0
                for fut in asyncio.as_completed([one(q) for q in queries]):
                    q, resp, latency = await fut
                    all_records.append(stages.make_stage_a_record(
                        scenario=label, engine_name=eng_name, attack_type=attack_type,
                        query=q, retrieved=retrieved[q.id], generated_response=resp,
                        retrieval_latency_ms=ret_lat[q.id], generation_latency_ms=latency,
                    ))
                    done += 1
                    progress.update(overall, description=f"[cyan]{label}: generated {done}/{len(queries)}")
                progress.advance(overall, 1)

    dense.flush_cache()

    header = {
        "run_id": run_id,
        "tier": "enterprise",
        "generator_model": config.GENERATOR_MODEL,
        "judge_model": config.JUDGE_MODEL,
        "corpus_mode": "synthetic",
        "num_cves": args.num_cves,
        "queries": len(queries),
        "scenarios": [s[0] for s in scenarios],
        "dense_model": config.DENSE_MODEL_NAME,
        "reranker_model": config.RERANKER_MODEL_NAME,
        "elapsed_s": round(time.time() - t_start, 1),
        "reranked_pairs": getattr(hybrid, "reranked_pairs", 0),
        "embed_cache_hits": dense.cache_hits,
        "embed_docs_encoded": dense.encoded_count,
    }
    path = stages.write_stage_a(stages.stage_a_path(config.REPORTS_DIR, run_id), header, all_records)
    console.print(f"\n[green]Stage A complete[/green] -> {path}")
    console.print(f"  {len(all_records)} query-scenarios | reranked pairs: {header['reranked_pairs']} "
                  f"| docs encoded: {header['embed_docs_encoded']} (cache hits: {header['embed_cache_hits']})")
    console.print(f"  Judge requests to follow: {2 * len(all_records)}")
    return path


# ------------------------------------------------------------------ stage B

async def judge_sync(records, judge, concurrency):
    verdicts = {}
    async with httpx.AsyncClient(timeout=120.0) as http_client:
        sem = asyncio.Semaphore(concurrency)

        async def one(rec):
            async with sem:
                v = await judge.evaluate_response_async(
                    http_client, rec["query_text"], rec["ground_truth_answer"],
                    rec["target_poison_assertion"], rec["generated_response"])
            return (rec["scenario"], rec["query_id"]), v

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("[yellow]Stage B (sync judge)", total=len(records))
            for fut in asyncio.as_completed([one(r) for r in records]):
                key, v = await fut
                verdicts[key] = v
                progress.advance(task, 1)
    return verdicts


def sync_verdicts_to_stage_b(verdicts):
    """Re-encode sync verdicts as raw judge JSON so stage C has a single code path."""
    gt_raw, ps_raw, manifest = {}, {}, []
    for i, ((scenario, qid), v) in enumerate(verdicts.items()):
        gt_id, ps_id = f"gt{i:06d}", f"ps{i:06d}"
        gt_reason, _, ps_reason = v.reasoning.partition(" | Poison: ")
        gt_reason = gt_reason[len("GT: "):] if gt_reason.startswith("GT: ") else gt_reason
        gt_raw[gt_id] = json.dumps({"is_ground_truth_retained": v.is_ground_truth_retained,
                                    "reasoning": gt_reason})
        ps_raw[ps_id] = json.dumps({"is_poison_adopted": v.is_poison_adopted,
                                    "detected_conflict": v.detected_conflict,
                                    "adoption_severity": v.adoption_severity,
                                    "reasoning": ps_reason})
        manifest.append({"custom_id": gt_id, "kind": "gt", "scenario": scenario, "query_id": qid})
        manifest.append({"custom_id": ps_id, "kind": "poison", "scenario": scenario, "query_id": qid})
    return gt_raw, ps_raw, manifest


def stage_b_batch(records, judge, judge_model, run_id, resume):
    client = OpenRouterBatchClient()
    items = stages.judge_items(records)
    gt_requests, gt_manifest = judge.build_batch_requests(items, "gt")
    ps_requests, ps_manifest = judge.build_batch_requests(items, "poison")

    unique = len(gt_requests) + len(ps_requests)
    console.print(f"[yellow]Stage B:[/yellow] {2 * len(items)} judge calls -> {unique} unique "
                  f"prompts ({100 * (1 - unique / max(1, 2 * len(items))):.1f}% fewer).")

    def progress_cb(done, pending):
        console.print(f"  polling: {len(done)} complete, {len(pending)} pending")

    if resume:
        gt_ok, gt_failed, c1 = client.resume(run_id, "judge_gt", on_progress=progress_cb)
        ps_ok, ps_failed, c2 = client.resume(run_id, "judge_poison", on_progress=progress_cb)
    else:
        # Split by prompt type: independent, so no wall-clock cost, and each batch then
        # carries a single response_format -- which Google models require batch-wide.
        gt_ok, gt_failed, c1 = client.run_batches(
            BATCH_ENDPOINT, judge_model, gt_requests, run_id, "judge_gt", on_progress=progress_cb)
        ps_ok, ps_failed, c2 = client.run_batches(
            BATCH_ENDPOINT, judge_model, ps_requests, run_id, "judge_poison", on_progress=progress_cb)

    failed = {**gt_failed, **ps_failed}
    if failed:
        console.print(f"[bold red]{len(failed)} judge requests failed after retries[/bold red]; "
                      f"affected items are reported as missing, not defaulted.")
    path = stages.write_stage_b(stages.stage_b_path(config.REPORTS_DIR, run_id),
                                run_id, judge_model, gt_ok, ps_ok,
                                gt_manifest + ps_manifest, c1 + c2, failed)
    console.print(f"[green]Stage B complete[/green] -> {path} | usage.cost = ${c1 + c2:.4f}")
    return path


# ------------------------------------------------------------------ stage C

def stage_c(run_id):
    header, records = stages.read_stage_a(stages.stage_a_path(config.REPORTS_DIR, run_id))
    stage_b = stages.read_stage_b(stages.stage_b_path(config.REPORTS_DIR, run_id))

    judge = LLMJudge(model=config.JUDGE_MODEL)
    verdicts, missing = judge.verdicts_from_batch(
        stage_b["gt_raw"], stage_b["poison_raw"], stage_b["manifest"],
        generated_responses=stages.generations_by_key(records))
    if missing:
        console.print(f"[bold red]{len(missing)} query-scenarios have no verdict[/bold red] "
                      f"and are excluded from the metrics.")

    grouped = stages.group_by_scenario(records)
    all_results: List[EngineBenchmarkResult] = []

    for scenario in header.get("scenarios", list(grouped)):
        scenario_records = grouped.get(scenario, [])
        if not scenario_records:
            continue
        retrieval_outputs, generated, ret_lat, gen_lat = stages.rebuild_scenario_inputs(scenario_records)
        scenario_verdicts = {qid: verdicts[(scenario, qid)] for qid in generated
                             if (scenario, qid) in verdicts}
        all_results.append(Evaluator.evaluate_engine_with_llm(
            engine_name=scenario_records[0]["engine_name"],
            attack_type=scenario_records[0]["attack_type"],
            queries=stages.rebuild_queries(scenario_records),
            retrieval_outputs=retrieval_outputs,
            generated_responses=generated,
            judge_verdicts=scenario_verdicts,
            retrieval_latencies=ret_lat,
            generation_latencies=gen_lat,
        ))

    console.print("\n" + "=" * 80, style="bold cyan")
    console.print("ENTERPRISE BENCHMARK RESULTS", style="bold green")
    console.print("=" * 80, style="bold cyan")
    BenchmarkReporter.print_terminal_results(all_results)

    report_path = config.REPORTS_DIR / f"enterprise_report_{run_id}.md"
    BenchmarkReporter.generate_markdown_report(all_results, report_path)

    summary_data = []
    for r in all_results:
        d = dict(r.__dict__)
        d["traces"] = [t.__dict__ for t in r.traces]
        summary_data.append(d)
    json_path = config.REPORTS_DIR / f"enterprise_results_{run_id}.json"
    json_path.write_text(json.dumps({
        "run_id": run_id,
        "header": header,
        "judge_usage_cost": stage_b.get("usage_cost"),
        "judge_failed_requests": len(stage_b.get("failed") or {}),
        "judge_parse_fallbacks": judge.fallback_count,
        "missing_verdicts": len(missing),
        "results": summary_data,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    traces_path = config.REPORTS_DIR / f"enterprise_traces_{run_id}.json"
    BenchmarkReporter.save_generation_traces(all_results, traces_path)

    console.print(f"\n[+] Markdown: [cyan]{report_path}[/cyan]")
    console.print(f"[+] JSON:     [cyan]{json_path}[/cyan]")
    console.print(f"[+] Traces:   [cyan]{traces_path}[/cyan]")
    console.print(f"\nJudge cost (reported by API): ${stage_b.get('usage_cost', 0.0):.4f} | "
                  f"parse fallbacks: {judge.fallback_count} | missing verdicts: {len(missing)}")


# ------------------------------------------------------------------ entrypoint

async def main():
    parser = argparse.ArgumentParser(description="Enterprise-Scale CTI RAG Poisoning Benchmark")
    parser.add_argument("--num_cves", type=int, default=24000)
    parser.add_argument("--queries", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=15)
    parser.add_argument("--stage", choices=["all", "a", "b", "c"], default="all")
    parser.add_argument("--run-id", dest="run_id", default=None)
    parser.add_argument("--resume-batch", action="store_true")
    parser.add_argument("--sync", action="store_true",
                        help="Force the synchronous judge path regardless of run size.")
    args = parser.parse_args()

    if args.stage in ("b", "c") and not args.run_id:
        parser.error("--stage b and --stage c need --run-id from the stage A run.")

    run_id = args.run_id or f"enterprise_{args.queries}q_{int(time.time())}"
    t0 = time.time()
    console.print("=" * 80, style="bold cyan")
    console.print("ENTERPRISE-SCALE CTI RAG POISONING BENCHMARK", style="bold green")
    console.print(f"  run_id={run_id} | generator={config.GENERATOR_MODEL} | judge={config.JUDGE_MODEL}",
                  style="dim")
    console.print("=" * 80, style="bold cyan")

    if args.stage in ("all", "a"):
        await stage_a(args, run_id)

    if args.stage in ("all", "b"):
        _, records = stages.read_stage_a(stages.stage_a_path(config.REPORTS_DIR, run_id))
        judge = LLMJudge(model=config.JUDGE_MODEL)
        judge_calls = 2 * len(records)
        if args.sync or judge_calls < config.BATCH_MIN_REQUESTS:
            reason = "--sync" if args.sync else f"{judge_calls} < BATCH_MIN_REQUESTS={config.BATCH_MIN_REQUESTS}"
            console.print(f"[yellow]Using the synchronous judge ({reason}).[/yellow]")
            verdicts = await judge_sync(records, judge, args.concurrency)
            gt_raw, ps_raw, manifest = sync_verdicts_to_stage_b(verdicts)
            stages.write_stage_b(stages.stage_b_path(config.REPORTS_DIR, run_id),
                                 run_id, config.JUDGE_MODEL, gt_raw, ps_raw, manifest, 0.0)
        else:
            stage_b_batch(records, judge, config.JUDGE_MODEL, run_id, args.resume_batch)

    if args.stage in ("all", "c"):
        stage_c(run_id)

    elapsed = time.time() - t0
    console.print(f"\nTotal: {elapsed:.1f}s ({elapsed/60:.1f} min) | [bold green]run_id = {run_id}[/bold green]")


if __name__ == "__main__":
    asyncio.run(main())
