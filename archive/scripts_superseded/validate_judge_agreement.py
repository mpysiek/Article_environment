#!/usr/bin/env python3
"""Krok 7: measure whether the split judge and the merged judge actually agree.

The benchmark's default is two independent judge calls per response, because a single call
that decides both questions at once can justify one answer with the other -- correlating
is_ground_truth_retained with is_poison_adopted, which is one of the things the benchmark
is supposed to measure. That is an argument, not a measurement. This script produces the
measurement: Cohen's kappa between the two modes on a sample of an existing stage A run.

    python scripts/validate_judge_agreement.py --run-id <id> --tier mid --sample 200

Reads stage_a_<run_id>.jsonl, so it costs one extra judge batch and no generation.
The sample MUST come from a stage A produced with the current dense model -- swapping the
bi-encoder changes retrieval, hence the contexts, hence the generations being judged.
"""
import argparse
import json
import random
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.table import Table

from src.config import config, CROSS_PROVIDER_TIERS
from src.evaluation import stages
from src.evaluation.llm_judge import LLMJudge
from src.llm.batch_client import OpenRouterBatchClient

console = Console()
BATCH_ENDPOINT = "/v1/chat/completions"


def cohens_kappa(a, b):
    """Cohen's kappa for two binary raters over the same items.

    Returns (kappa, observed_agreement). kappa is None when one rater is constant, since
    expected agreement is then 1.0 and the statistic is undefined -- reporting 0.0 there
    would read as 'no agreement' when the truth is 'not computable'.
    """
    n = len(a)
    if n == 0:
        return None, 0.0
    observed = sum(1 for x, y in zip(a, b) if x == y) / n
    pa1, pb1 = sum(a) / n, sum(b) / n
    expected = pa1 * pb1 + (1 - pa1) * (1 - pb1)
    if abs(1.0 - expected) < 1e-12:
        return None, observed
    return (observed - expected) / (1 - expected), observed


def confusion(a, b):
    return {
        "both_true": sum(1 for x, y in zip(a, b) if x and y),
        "split_only": sum(1 for x, y in zip(a, b) if x and not y),
        "merged_only": sum(1 for x, y in zip(a, b) if not x and y),
        "both_false": sum(1 for x, y in zip(a, b) if not x and not y),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", dest="run_id", required=True)
    ap.add_argument("--tier", choices=["mid", "low", "baseline"], default="mid")
    ap.add_argument("--sample", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    tier_info = CROSS_PROVIDER_TIERS[args.tier]
    judge_model = tier_info["judge_model"]

    header, records = stages.read_stage_a(stages.stage_a_path(config.REPORTS_DIR, args.run_id))
    stages.assert_tier_matches(header, args.tier, args.run_id)

    recorded_dense = header.get("dense_model")
    if recorded_dense and recorded_dense != config.DENSE_MODEL_NAME:
        console.print(f"[bold red]Refusing to run.[/bold red] Stage A used dense model "
                      f"'{recorded_dense}' but config now says '{config.DENSE_MODEL_NAME}'. "
                      f"Kappa measured here would not describe the configuration you run.")
        sys.exit(1)

    rng = random.Random(args.seed)
    sample = rng.sample(records, min(args.sample, len(records)))
    console.print(f"Sampling {len(sample)} of {len(records)} query-scenarios from run {args.run_id}.")

    items = stages.judge_items(sample)
    generated = stages.generations_by_key(sample)

    split_judge = LLMJudge(model=judge_model)
    merged_judge = LLMJudge(model=judge_model)

    gt_reqs, gt_man = split_judge.build_batch_requests(items, "gt")
    ps_reqs, ps_man = split_judge.build_batch_requests(items, "poison")
    mg_reqs, mg_man = merged_judge.build_batch_requests(items, "merged")

    client = OpenRouterBatchClient()
    run_id = f"{args.run_id}_kappa_{int(time.time())}"

    def progress(done, pending):
        console.print(f"  polling: {len(done)} complete, {len(pending)} pending")

    console.print(f"[yellow]Submitting {len(gt_reqs)+len(ps_reqs)} split + {len(mg_reqs)} merged requests...[/yellow]")
    gt_ok, gt_failed, c1 = client.run_batches(BATCH_ENDPOINT, judge_model, gt_reqs, run_id, "kappa_gt", on_progress=progress)
    ps_ok, ps_failed, c2 = client.run_batches(BATCH_ENDPOINT, judge_model, ps_reqs, run_id, "kappa_poison", on_progress=progress)
    mg_ok, mg_failed, c3 = client.run_batches(BATCH_ENDPOINT, judge_model, mg_reqs, run_id, "kappa_merged", on_progress=progress)

    split_v, split_missing = split_judge.verdicts_from_batch(gt_ok, ps_ok, gt_man + ps_man, generated)
    merged_v, merged_missing = merged_judge.verdicts_from_merged_batch(mg_ok, mg_man, generated)

    keys = sorted(set(split_v) & set(merged_v))
    console.print(f"Comparable items: {len(keys)} "
                  f"(split missing {len(split_missing)}, merged missing {len(merged_missing)})")

    report = {
        "run_id": args.run_id,
        "kappa_run_id": run_id,
        "tier": args.tier,
        "judge_model": judge_model,
        "sample_requested": args.sample,
        "compared": len(keys),
        "usage_cost": c1 + c2 + c3,
        "failed_requests": len(gt_failed) + len(ps_failed) + len(mg_failed),
        "fallback_count_split": split_judge.fallback_count,
        "fallback_count_merged": merged_judge.fallback_count,
        "fields": {},
    }

    table = Table(show_header=True, header_style="bold magenta")
    for col in ("Field", "Cohen's kappa", "Observed agreement", "Split only", "Merged only"):
        table.add_column(col)

    for field in ("is_poison_adopted", "is_ground_truth_retained", "detected_conflict"):
        a = [getattr(split_v[k], field) for k in keys]
        b = [getattr(merged_v[k], field) for k in keys]
        kappa, observed = cohens_kappa(a, b)
        conf = confusion(a, b)
        report["fields"][field] = {
            "kappa": kappa, "observed_agreement": observed, "confusion": conf,
            "split_positive_rate": (sum(a) / len(a)) if a else None,
            "merged_positive_rate": (sum(b) / len(b)) if b else None,
        }
        table.add_row(field,
                      "undefined (constant rater)" if kappa is None else f"{kappa:.3f}",
                      f"{observed:.1%}", str(conf["split_only"]), str(conf["merged_only"]))

    console.print(table)
    console.print(f"\nParse fallbacks -- split: {split_judge.fallback_count}, "
                  f"merged: {merged_judge.fallback_count}")
    console.print(f"Cost of this experiment: ${c1 + c2 + c3:.4f}")

    out = config.REPORTS_DIR / f"judge_agreement_{args.run_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    console.print(f"\n[green]Written[/green] -> {out}")
    console.print("Interpretation: kappa > 0.85 on both is_poison_adopted and "
                  "is_ground_truth_retained would make merging defensible. Anything lower "
                  "is the numeric case for keeping the two calls separate.")


if __name__ == "__main__":
    main()
