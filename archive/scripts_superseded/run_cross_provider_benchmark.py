#!/usr/bin/env python3
"""Cross-provider RAG poisoning benchmark, split into three stages.

    A  retrieve + generate     synchronous (async httpx), minutes
    B  judge                   OpenRouter Batch API, up to 24h, ~50% cheaper
    C  join + evaluate         local, seconds

Generation stays synchronous on purpose: nothing downstream of the judge waits on it, so
the judge is the only stage that can absorb a 24h completion window -- and keeping
generation synchronous is what preserves avg_generation_latency_ms as a real measurement.

  python scripts/run_cross_provider_benchmark.py --tier mid --queries 1000            # all stages
  python scripts/run_cross_provider_benchmark.py --tier mid --queries 1000 --stage a
  python scripts/run_cross_provider_benchmark.py --tier mid --stage b --run-id <id>
  python scripts/run_cross_provider_benchmark.py --tier mid --stage b --run-id <id> --resume-batch
  python scripts/run_cross_provider_benchmark.py --tier mid --stage c --run-id <id>
"""
import argparse
import asyncio
import json
import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from typing import Dict, List, Any, Tuple
import httpx
from dataclasses import asdict

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

from src.config import config, CROSS_PROVIDER_TIERS
from src.corpus.real_cti_loader import RealCTILoader
from src.corpus.real_query_loader import build_real_gold_queries
from src.corpus.large_cti_generator import generate_enterprise_cti_corpus, build_100_gold_queries
from src.engines.retrievers import BM25Retriever, DenseFAISSRetriever, HybridRerankRetriever, GraphRAGRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.llm.async_openrouter_client import AsyncOpenRouterClient
from src.llm.batch_client import OpenRouterBatchClient
from src.llm.rag_generator import RAGGenerator
from src.evaluation.llm_judge import LLMJudge, JudgeVerdict
from src.evaluation.metrics import Evaluator, EngineBenchmarkResult
from src.evaluation import stages

console = Console()

BATCH_ENDPOINT = "/v1/chat/completions"


def scenario_matrix(corpora, bm25, dense, hybrid, graph):
    return [
        ("Baseline Sparse", "clean", bm25, corpora["clean"]),
        ("Baseline Dense", "clean", dense, corpora["clean"]),
        ("Baseline Hybrid", "clean", hybrid, corpora["clean"]),
        ("Baseline Graph", "clean", graph, corpora["clean"]),

        ("Poisoned Sparse", "sparse", bm25, corpora["sparse"]),
        ("Poisoned Dense", "dense", dense, corpora["dense"]),
        ("Poisoned Hybrid", "hybrid", hybrid, corpora["hybrid"]),
        ("Poisoned Graph", "graph", graph, corpora["graph"]),

        ("Cross Sparse (Hybrid)", "cross_sparse", hybrid, corpora["sparse"]),
        ("Cross Dense (Hybrid)", "cross_dense", hybrid, corpora["dense"]),
    ]


# ------------------------------------------------------------------ stage A

async def generate_for_scenario(
    scenario_name, attack_type, engine, corpus, queries,
    generator, http_client, progress, task_id
) -> List[Dict[str, Any]]:
    progress.update(task_id, description=f"[cyan]{scenario_name}: Building index...")
    engine.build_index(corpus)

    progress.update(task_id, description=f"[cyan]{scenario_name}: Retrieving...")
    retrieved: Dict[str, Any] = {}
    retrieval_latencies: Dict[str, float] = {}
    for q in queries:
        t0 = time.time()
        retrieved[q.id] = engine.retrieve(q.query_text)
        retrieval_latencies[q.id] = (time.time() - t0) * 1000.0

    progress.update(task_id, description=f"[cyan]{scenario_name}: Generating...")

    async def one(q):
        t0 = time.time()
        resp = await generator.generate_response_async(http_client, q.query_text, retrieved[q.id])
        return q, resp, (time.time() - t0) * 1000.0

    records = []
    tasks = [one(q) for q in queries]
    done = 0
    for fut in asyncio.as_completed(tasks):
        q, resp, latency = await fut
        records.append(stages.make_stage_a_record(
            scenario=scenario_name,
            engine_name=engine.name,
            attack_type=attack_type,
            query=q,
            retrieved=retrieved[q.id],
            generated_response=resp,
            retrieval_latency_ms=retrieval_latencies[q.id],
            generation_latency_ms=latency,
        ))
        done += 1
        progress.update(task_id, description=f"[cyan]{scenario_name}: generated {done}/{len(queries)}")

    progress.update(task_id, description=f"[green]{scenario_name}: done")
    progress.advance(task_id, 1)
    return records


async def stage_a(args, tier_info, run_id) -> Path:
    console.print("[yellow]Loading corpus...[/yellow]")
    if args.corpus_mode == "real":
        clean_corpus = RealCTILoader().load_full_real_corpus(target_cves=args.num_cves)
        queries = build_real_gold_queries(args.queries)
    else:
        clean_corpus = generate_enterprise_cti_corpus(num_cves=args.num_cves)
        all_queries = build_100_gold_queries()
        if args.queries > len(all_queries):
            raise ValueError(
                f"Synthetic query set has {len(all_queries)} queries but --queries "
                f"{args.queries} was requested. Use --corpus_mode real for larger runs."
            )
        queries = all_queries[:args.queries]

    console.print(f"Loaded {len(clean_corpus)} documents and {len(queries)} queries.")

    console.print("[yellow]Generating poisoned corpora...[/yellow]")
    poison_manager = CorpusPoisonManager()
    corpora = {
        "clean": clean_corpus,
        "sparse": poison_manager.generate_poisoned_corpus(clean_corpus, queries, "sparse"),
        "dense": poison_manager.generate_poisoned_corpus(clean_corpus, queries, "dense"),
        "hybrid": poison_manager.generate_poisoned_corpus(clean_corpus, queries, "hybrid"),
        "graph": poison_manager.generate_poisoned_corpus(clean_corpus, queries, "graph"),
    }

    bm25 = BM25Retriever()
    dense = DenseFAISSRetriever()
    hybrid = HybridRerankRetriever(bm25, dense)
    graph = GraphRAGRetriever()

    async_client = AsyncOpenRouterClient(concurrency=args.concurrency)
    generator = RAGGenerator(async_client=async_client, model=tier_info["generator_model"])

    scenarios = scenario_matrix(corpora, bm25, dense, hybrid, graph)
    all_records: List[Dict[str, Any]] = []
    t_start = time.time()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TimeElapsedColumn(), console=console) as progress:
        overall = progress.add_task("[bold magenta]Stage A: retrieve + generate", total=len(scenarios))
        async with httpx.AsyncClient(timeout=120.0) as http_client:
            for name, attack_type, engine, corpus in scenarios:
                task_id = progress.add_task(f"[cyan]{name}...", total=1)
                all_records += await generate_for_scenario(
                    name, attack_type, engine, corpus, queries,
                    generator, http_client, progress, task_id
                )
                progress.advance(overall, 1)

    # Any vectors still only in memory belong on disk before the process exits.
    dense.flush_cache()

    header = {
        "run_id": run_id,
        "tier": args.tier,
        "generator_model": tier_info["generator_model"],
        "judge_model": tier_info["judge_model"],
        "corpus_mode": args.corpus_mode,
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

async def judge_sync(records, judge, concurrency) -> Tuple[Dict[Tuple[str, str], JudgeVerdict], float]:
    """Fallback path for runs too small to be worth queueing."""
    verdicts: Dict[Tuple[str, str], JudgeVerdict] = {}
    async with httpx.AsyncClient(timeout=120.0) as http_client:
        sem = asyncio.Semaphore(concurrency)

        async def one(rec):
            async with sem:
                v = await judge.evaluate_response_async(
                    http_client, rec["query_text"], rec["ground_truth_answer"],
                    rec["target_poison_assertion"], rec["generated_response"]
                )
            return (rec["scenario"], rec["query_id"]), v

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("[yellow]Stage B (sync judge)", total=len(records))
            for fut in asyncio.as_completed([one(r) for r in records]):
                key, v = await fut
                verdicts[key] = v
                progress.advance(task, 1)
    return verdicts, 0.0


def stage_b_batch(records, judge, judge_model, run_id, resume: bool) -> Path:
    client = OpenRouterBatchClient()
    items = stages.judge_items(records)
    gt_requests, gt_manifest = judge.build_batch_requests(items, "gt")
    ps_requests, ps_manifest = judge.build_batch_requests(items, "poison")
    manifest = gt_manifest + ps_manifest

    total_items = len(items)
    unique = len(gt_requests) + len(ps_requests)
    console.print(f"[yellow]Stage B:[/yellow] {2 * total_items} judge calls -> "
                  f"{unique} unique prompts after deduplication "
                  f"({100 * (1 - unique / max(1, 2 * total_items)):.1f}% fewer).")

    def progress_cb(done, pending):
        console.print(f"  polling: {len(done)} complete, {len(pending)} pending")

    if resume:
        console.print("[yellow]Resuming previously submitted batches...[/yellow]")
        gt_ok, gt_failed, gt_cost = client.resume(run_id, "judge_gt", on_progress=progress_cb)
        ps_ok, ps_failed, ps_cost = client.resume(run_id, "judge_poison", on_progress=progress_cb)
    else:
        # GT and poison go as separate batch sets. They are independent, so this costs no
        # wall clock -- and it keeps each batch to a single response_format, which Google
        # models require batch-wide.
        gt_ok, gt_failed, gt_cost = client.run_batches(
            BATCH_ENDPOINT, judge_model, gt_requests, run_id, "judge_gt", on_progress=progress_cb)
        ps_ok, ps_failed, ps_cost = client.run_batches(
            BATCH_ENDPOINT, judge_model, ps_requests, run_id, "judge_poison", on_progress=progress_cb)

    cost = gt_cost + ps_cost
    failed = {**gt_failed, **ps_failed}
    if failed:
        console.print(f"[bold red]{len(failed)} judge requests failed after retries.[/bold red] "
                      f"Affected query-scenarios are reported as missing, not defaulted.")

    path = stages.write_stage_b(
        stages.stage_b_path(config.REPORTS_DIR, run_id),
        run_id, judge_model, gt_ok, ps_ok, manifest, cost, failed
    )
    console.print(f"[green]Stage B complete[/green] -> {path} | reported usage.cost = ${cost:.4f}")
    return path


# ------------------------------------------------------------------ stage C

def stage_c(args, run_id, tier_info):
    header, records = stages.read_stage_a(stages.stage_a_path(config.REPORTS_DIR, run_id))
    stages.assert_tier_matches(header, args.tier, run_id)

    judge = LLMJudge(model=tier_info["judge_model"])
    stage_b = stages.read_stage_b(stages.stage_b_path(config.REPORTS_DIR, run_id))

    verdicts, missing = judge.verdicts_from_batch(
        stage_b["gt_raw"], stage_b["poison_raw"], stage_b["manifest"],
        generated_responses=stages.generations_by_key(records),
    )
    if missing:
        console.print(f"[bold red]{len(missing)} query-scenarios have no verdict[/bold red] "
                      f"and are excluded from the metrics.")

    grouped = stages.group_by_scenario(records)
    results: List[EngineBenchmarkResult] = []
    all_traces = []

    for scenario in header.get("scenarios", list(grouped)):
        scenario_records = grouped.get(scenario, [])
        if not scenario_records:
            continue
        retrieval_outputs, generated, ret_lat, gen_lat = stages.rebuild_scenario_inputs(scenario_records)
        queries = stages.rebuild_queries(scenario_records)
        scenario_verdicts = {
            qid: verdicts[(scenario, qid)]
            for qid in generated if (scenario, qid) in verdicts
        }
        res = Evaluator.evaluate_engine_with_llm(
            engine_name=scenario_records[0]["engine_name"],
            attack_type=scenario_records[0]["attack_type"],
            queries=queries,
            retrieval_outputs=retrieval_outputs,
            generated_responses=generated,
            judge_verdicts=scenario_verdicts,
            retrieval_latencies=ret_lat,
            generation_latencies=gen_lat,
        )
        results.append(res)
        all_traces.extend(res.traces)

    _write_reports(results, all_traces, header, stage_b, judge, missing, run_id)


def _write_reports(results, all_traces, header, stage_b, judge, missing, run_id):
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    from src.visualization.reporter import BenchmarkReporter

    BenchmarkReporter.generate_markdown_report(
        results, config.REPORTS_DIR / f"cross_provider_report_{run_id}.md")

    summary = {
        "run_id": run_id,
        "header": header,
        "judge_usage_cost": stage_b.get("usage_cost"),
        "judge_failed_requests": len(stage_b.get("failed") or {}),
        "judge_parse_fallbacks": judge.fallback_count,
        "missing_verdicts": len(missing),
        "results": [
            {
                "engine": r.engine_name,
                "attack_type": r.attack_type,
                "retrieval_asr_top1": r.retrieval_asr_top1,
                "retrieval_asr_top5": r.retrieval_asr_top5,
                "clean_recall_top5": r.clean_recall_top5,
                "clean_mrr": r.clean_mrr,
                "generation_asr": r.generation_asr,
                "gt_retention": r.ground_truth_retention,
                "conflict_detection": r.conflict_detection_rate,
                "avg_retrieval_latency_ms": r.avg_retrieval_latency_ms,
                "avg_generation_latency_ms": r.avg_generation_latency_ms,
                "total_queries": r.total_queries,
            } for r in results
        ],
    }
    (config.REPORTS_DIR / f"cross_provider_results_{run_id}.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    (config.REPORTS_DIR / f"cross_provider_traces_{run_id}.json").write_text(
        json.dumps([asdict(t) for t in all_traces], indent=2), encoding="utf-8")

    table = Table(show_header=True, header_style="bold magenta")
    for col in ("Engine", "Attack", "Retr ASR@5", "Gen ASR", "GT Retention"):
        table.add_column(col, justify="right" if col not in ("Engine", "Attack") else "left")
    for r in results:
        table.add_row(r.engine_name, r.attack_type, f"{r.retrieval_asr_top5:.1%}",
                      f"{r.generation_asr:.1%}", f"{r.ground_truth_retention:.1%}")
    console.print("\n[bold]Benchmark Summary[/bold]")
    console.print(table)
    console.print(f"\nJudge cost (reported by API): ${stage_b.get('usage_cost', 0.0):.4f} | "
                  f"parse fallbacks: {judge.fallback_count} | missing verdicts: {len(missing)}")


# ------------------------------------------------------------------ entrypoint

async def main():
    parser = argparse.ArgumentParser(description="Cross-Provider RAG Poisoning Benchmark")
    parser.add_argument("--tier", choices=["mid", "low", "baseline"], default="mid")
    parser.add_argument("--corpus_mode", choices=["real", "synthetic"], default="real")
    parser.add_argument("--num_cves", type=int, default=24000)
    parser.add_argument("--queries", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=15)
    parser.add_argument("--stage", choices=["all", "a", "b", "c"], default="all")
    parser.add_argument("--run-id", dest="run_id", default=None,
                        help="Identifies a run across stages. Required for --stage b/c.")
    parser.add_argument("--resume-batch", action="store_true",
                        help="Re-enter the poll loop for batches this run already submitted.")
    parser.add_argument("--sync", action="store_true",
                        help="Force the synchronous judge path regardless of run size.")
    args = parser.parse_args()

    tier_info = CROSS_PROVIDER_TIERS[args.tier]
    run_id = args.run_id or f"{args.tier}_{args.corpus_mode}_{args.queries}q_{int(time.time())}"

    if args.stage in ("b", "c") and not args.run_id:
        parser.error("--stage b and --stage c need --run-id from the stage A run.")

    console.print(f"[bold blue]Cross-Provider Benchmark[/bold blue] "
                  f"tier={args.tier} run_id={run_id}")
    console.print(f"  generator: {tier_info['generator_model']}")
    console.print(f"  judge:     {tier_info['judge_model']}")

    if args.stage in ("all", "a"):
        await stage_a(args, tier_info, run_id)

    if args.stage in ("all", "b"):
        header, records = stages.read_stage_a(stages.stage_a_path(config.REPORTS_DIR, run_id))
        stages.assert_tier_matches(header, args.tier, run_id)
        judge = LLMJudge(model=tier_info["judge_model"])
        judge_calls = 2 * len(records)

        if args.sync or judge_calls < config.BATCH_MIN_REQUESTS:
            reason = "--sync" if args.sync else f"{judge_calls} < BATCH_MIN_REQUESTS={config.BATCH_MIN_REQUESTS}"
            console.print(f"[yellow]Using the synchronous judge ({reason}).[/yellow]")
            verdicts, cost = await judge_sync(records, judge, args.concurrency)
            # Store sync verdicts in the stage B shape so stage C is identical either way.
            gt_raw, ps_raw, manifest = _sync_verdicts_to_stage_b(verdicts)
            stages.write_stage_b(stages.stage_b_path(config.REPORTS_DIR, run_id),
                                 run_id, tier_info["judge_model"], gt_raw, ps_raw, manifest, cost)
        else:
            stage_b_batch(records, judge, tier_info["judge_model"], run_id, args.resume_batch)

    if args.stage in ("all", "c"):
        stage_c(args, run_id, tier_info)

    console.print(f"\n[bold green]run_id = {run_id}[/bold green]")


def _sync_verdicts_to_stage_b(verdicts):
    """Re-encode sync verdicts as raw judge JSON so stage C has one code path only."""
    gt_raw, ps_raw, manifest = {}, {}, []
    for i, ((scenario, qid), v) in enumerate(verdicts.items()):
        gt_id, ps_id = f"gt{i:06d}", f"ps{i:06d}"
        # JudgeVerdict.reasoning is the two halves already joined; split them back so the
        # re-encoded JSON round-trips to the identical string through stage C's parsers.
        gt_reason, _, ps_reason = v.reasoning.partition(" | Poison: ")
        gt_reason = gt_reason[len("GT: "):] if gt_reason.startswith("GT: ") else gt_reason
        gt_raw[gt_id] = json.dumps({
            "is_ground_truth_retained": v.is_ground_truth_retained,
            "reasoning": gt_reason,
        })
        ps_raw[ps_id] = json.dumps({
            "is_poison_adopted": v.is_poison_adopted,
            "detected_conflict": v.detected_conflict,
            "adoption_severity": v.adoption_severity,
            "reasoning": ps_reason,
        })
        manifest.append({"custom_id": gt_id, "kind": "gt", "scenario": scenario, "query_id": qid})
        manifest.append({"custom_id": ps_id, "kind": "poison", "scenario": scenario, "query_id": qid})
    return gt_raw, ps_raw, manifest


if __name__ == "__main__":
    asyncio.run(main())
