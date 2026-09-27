#!/usr/bin/env python3
"""Krok 0: confirm the Batch API works for this project's judge models before refactoring.

Three questions, each of which would force a redesign if the answer is no:

  0a  does the model support batching at all?
  0b  is a full BATCH_CHUNK_SIZE submission accepted? (the API documents no maximum)
  0c  does response_format json_object survive a batch round-trip?

Costs a few cents. Run it before the first full benchmark, and again if the judge model
changes.

  export OPENROUTER_API_KEY=sk-or-...
  python scripts/batch_smoke_test.py --models meta-llama/llama-3.3-70b-instruct
  python scripts/batch_smoke_test.py --models anthropic/claude-haiku-4.5 --check-chunk-size
"""
import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import config
from src.llm.batch_client import OpenRouterBatchClient, BatchSubmissionError

ENDPOINT = "/v1/chat/completions"


def _run(client, model, requests, label, poll_interval):
    print(f"\n--- {label}: {len(requests)} request(s) on {model} ---")
    t0 = time.time()
    try:
        batch_ids = client.submit_all(ENDPOINT, model, requests)
    except BatchSubmissionError as e:
        print(f"  SUBMIT FAILED: {e}")
        return None
    print(f"  submitted: {batch_ids}")

    def progress(done, pending):
        print(f"  [{time.time()-t0:6.0f}s] done={len(done)} pending={len(pending)}")

    try:
        batches = client.wait_for_terminal(batch_ids, poll_interval, progress)
        ok, failed, cost = client.collect(batches)
    except BatchSubmissionError as e:
        print(f"  FAILED: {e}")
        return None

    print(f"  completed in {time.time()-t0:.0f}s | ok={len(ok)} failed={len(failed)} "
          f"| usage.cost={cost}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True,
                    help="OpenRouter model slugs to probe (use the judge models from CROSS_PROVIDER_TIERS)")
    ap.add_argument("--check-chunk-size", action="store_true",
                    help="also submit a full BATCH_CHUNK_SIZE batch (costs real money)")
    ap.add_argument("--chunk-size", type=int, default=config.BATCH_CHUNK_SIZE)
    ap.add_argument("--poll-interval", type=int, default=15)
    args = ap.parse_args()

    if not config.OPENROUTER_API_KEY:
        sys.exit("OPENROUTER_API_KEY is not set.")

    client = OpenRouterBatchClient(state_dir=PROJECT_ROOT / "outputs" / "reports" / "smoke")
    summary = {}

    for model in args.models:
        result = {"batch": False, "json_mode": False, "chunk_size": None}

        # 0a -- plain batch support
        basic = [
            {"custom_id": "smoke-0001",
             "body": {"messages": [{"role": "user", "content": "Reply with the word OK."}],
                      "max_tokens": 16, "temperature": 0.0}},
            {"custom_id": "smoke-0002",
             "body": {"messages": [{"role": "user", "content": "Reply with the word FINE."}],
                      "max_tokens": 16, "temperature": 0.0}},
        ]
        if _run(client, model, basic, "0a batch support", args.poll_interval) is not None:
            result["batch"] = True

        # 0c -- JSON mode under batch
        if result["batch"]:
            json_reqs = [
                {"custom_id": f"smoke-json-{i:04d}",
                 "body": {"messages": [
                     {"role": "system", "content": "You are a precise JSON-only judge. Always output valid JSON."},
                     {"role": "user", "content": 'Respond ONLY with valid JSON: {"is_ok": true, "reasoning": "<short>"}'}],
                     "max_tokens": config.JUDGE_MAX_TOKENS, "temperature": 0.0,
                     "response_format": {"type": "json_object"}}}
                for i in (1, 2)
            ]
            ok = _run(client, model, json_reqs, "0c JSON mode", args.poll_interval)
            if ok:
                parsed = 0
                for cid, content in ok.items():
                    try:
                        json.loads(content)
                        parsed += 1
                    except json.JSONDecodeError:
                        print(f"  {cid}: NOT valid JSON -> {content[:120]!r}")
                result["json_mode"] = parsed == len(ok)

        # 0b -- chunk size ceiling
        if result["batch"] and args.check_chunk_size:
            big = [
                {"custom_id": f"smoke-bulk-{i:06d}",
                 "body": {"messages": [{"role": "user", "content": f"Reply with the number {i}."}],
                          "max_tokens": 8, "temperature": 0.0}}
                for i in range(args.chunk_size)
            ]
            payload_mb = len(OpenRouterBatchClient.build_payload(ENDPOINT, model, big)) / 1e6
            print(f"\n  (payload is {payload_mb:.1f} MB)")
            if _run(client, model, big, f"0b chunk size {args.chunk_size}", args.poll_interval) is not None:
                result["chunk_size"] = args.chunk_size

        summary[model] = result

    print("\n================ SUMMARY ================")
    for model, r in summary.items():
        print(f"{model}")
        print(f"  batch supported : {r['batch']}")
        print(f"  json_object     : {r['json_mode']}")
        print(f"  chunk {args.chunk_size:<10}: {'ok' if r['chunk_size'] else 'not tested' if not args.check_chunk_size else 'FAILED'}")
    print("\nIf a judge model fails here, change that tier's judge model or keep the tier on")
    print("the synchronous path -- do not work around it in the batch client.")


if __name__ == "__main__":
    main()
