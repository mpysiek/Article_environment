"""Stage handoff for the split benchmark pipeline.

A run is three stages so that the judge can go through the Batch API:

    A  retrieve + generate            synchronous, minutes
    B  judge                          Batch API, up to 24h
    C  join + evaluate + report       local, seconds

Stage A and B communicate through files rather than memory, which is what makes a run
survivable: the Batch API is asynchronous, and a process that dies while a batch is in
flight must not throw away work that has already been paid for.

Stage A persists complete RetrievalResult records, not just document ids. Evaluator reads
`.is_poisoned`, `.title`, `.text` and `.rank` off them for both the ASR counts and the
traces, so a stage C rebuilt from ids alone would silently report zero retrieval ASR.
"""

import json
from pathlib import Path
import time
from typing import List, Dict, Any, Tuple, Optional

from src.corpus.dataset import RetrievalResult, GoldQuery

STAGE_A_VERSION = 1


# --------------------------------------------------------------------- serialization

def retrieval_result_to_dict(r: RetrievalResult) -> Dict[str, Any]:
    return {
        "doc_id": r.doc_id,
        "score": float(r.score),
        "rank": int(r.rank),
        "title": r.title,
        "text": r.text,
        "is_poisoned": bool(r.is_poisoned),
        "doc_type": r.doc_type,
        "poison_target_query": r.poison_target_query,
        "poison_type": r.poison_type,
        "metadata": r.metadata,
    }


def retrieval_result_from_dict(d: Dict[str, Any]) -> RetrievalResult:
    return RetrievalResult(
        doc_id=d["doc_id"],
        score=d["score"],
        rank=d["rank"],
        title=d["title"],
        text=d["text"],
        is_poisoned=d["is_poisoned"],
        doc_type=d["doc_type"],
        poison_target_query=d.get("poison_target_query"),
        poison_type=d.get("poison_type"),
        metadata=d.get("metadata", {}),
    )


def make_stage_a_record(
    scenario: str,
    engine_name: str,
    attack_type: str,
    query: GoldQuery,
    retrieved: List[RetrievalResult],
    generated_response: str,
    retrieval_latency_ms: float,
    generation_latency_ms: float,
    injected_assertion: Optional[str] = None,
    isolated_target: bool = False
) -> Dict[str, Any]:
    return {
        "scenario": scenario,
        "engine_name": engine_name,
        "attack_type": attack_type,
        "query_id": query.id,
        "query_text": query.query_text,
        "category": query.category,
        # Required by Evaluator for clean_recall_top5 / clean_mrr. Without it stage C
        # would report those as zero and the numbers would look like a retrieval failure.
        "ground_truth_doc_ids": list(query.ground_truth_doc_ids),
        "ground_truth_answer": query.ground_truth_answer,
        "target_poison_assertion": injected_assertion if injected_assertion is not None else query.target_poison_assertion,
        "generated_response": generated_response,
        "retrieval_latency_ms": retrieval_latency_ms,
        "generation_latency_ms": generation_latency_ms,
        "isolated_target": isolated_target,
        "retrieved": [retrieval_result_to_dict(r) for r in retrieved],
    }


def execute_isolated_retrieval(
    engine: Any,
    clean_docs: List[Any],
    poison_payloads: Dict[str, List[Any]],
    queries: List[GoldQuery],
    top_k: int = 5
) -> Tuple[Dict[str, List[RetrievalResult]], Dict[str, float]]:
    """Executes the Recommendation 3 isolated per-query retrieval protocol.

    For each evaluation query Q_i:
      1. An isolated index instance is prepared containing clean_docs plus ONLY the poison
         documents generated for Q_i (zero foreign poisons).
      2. Retrieves top_k results for Q_i.
    Returns:
      (retrieval_outputs, retrieval_latencies)
    """
    retrieval_outputs: Dict[str, List[RetrievalResult]] = {}
    retrieval_latencies: Dict[str, float] = {}

    for q in queries:
        q_poisons = poison_payloads.get(q.id, [])
        index_docs = clean_docs + q_poisons if q_poisons else clean_docs
        engine.build_index(index_docs)

        t0 = time.perf_counter()
        results = engine.retrieve(q.query_text, top_k=top_k)
        ret_latency_ms = (time.perf_counter() - t0) * 1000.0

        retrieval_outputs[q.id] = results
        retrieval_latencies[q.id] = ret_latency_ms

    return retrieval_outputs, retrieval_latencies


def execute_shared_retrieval(
    engine: Any,
    corpus: List[Any],
    queries: List[GoldQuery],
    top_k: int = 5
) -> Tuple[Dict[str, List[RetrievalResult]], Dict[str, float]]:
    """Executes shared-index retrieval across all queries."""
    engine.build_index(corpus)
    retrieval_outputs: Dict[str, List[RetrievalResult]] = {}
    retrieval_latencies: Dict[str, float] = {}

    for q in queries:
        t0 = time.perf_counter()
        results = engine.retrieve(q.query_text, top_k=top_k)
        ret_latency_ms = (time.perf_counter() - t0) * 1000.0

        retrieval_outputs[q.id] = results
        retrieval_latencies[q.id] = ret_latency_ms

    return retrieval_outputs, retrieval_latencies


# --------------------------------------------------------------------- stage A files

def stage_a_path(reports_dir: Path, run_id: str) -> Path:
    return Path(reports_dir) / f"stage_a_{run_id}.jsonl"


def write_stage_a(path: Path, header: Dict[str, Any], records: List[Dict[str, Any]]) -> Path:
    """Write the stage A handoff: one header line, then one record per query-scenario."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"_header": {**header, "version": STAGE_A_VERSION}},
                           ensure_ascii=False) + "\n")
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return path


def read_stage_a(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"No stage A handoff at {path}. Run --stage a first (or pass the right --run-id)."
        )
    header: Dict[str, Any] = {}
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "_header" in obj:
                header = obj["_header"]
            else:
                records.append(obj)
    return header, records


def assert_tier_matches(header: Dict[str, Any], tier: str, run_id: str):
    """A later stage run with a different --tier would join cleanly and mislabel everything.

    The judge model is fixed per batch and the generator model is baked into stage A, so
    the tier is part of the run's identity, not a per-invocation option.
    """
    recorded = header.get("tier")
    if recorded is not None and recorded != tier:
        raise ValueError(
            f"Run '{run_id}' was generated with tier '{recorded}' but this stage was "
            f"invoked with tier '{tier}'. Re-run with --tier {recorded}."
        )


# --------------------------------------------------------------------- reassembly

def group_by_scenario(records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for rec in records:
        grouped.setdefault(rec["scenario"], []).append(rec)
    return grouped


def rebuild_scenario_inputs(
    scenario_records: List[Dict[str, Any]]
) -> Tuple[Dict[str, List[RetrievalResult]], Dict[str, str], Dict[str, float], Dict[str, float]]:
    """Rebuild the four dicts Evaluator.evaluate_engine_with_llm expects, keyed by query id."""
    retrieval_outputs: Dict[str, List[RetrievalResult]] = {}
    generated_responses: Dict[str, str] = {}
    retrieval_latencies: Dict[str, float] = {}
    generation_latencies: Dict[str, float] = {}
    for rec in scenario_records:
        qid = rec["query_id"]
        retrieval_outputs[qid] = [retrieval_result_from_dict(d) for d in rec["retrieved"]]
        generated_responses[qid] = rec["generated_response"]
        retrieval_latencies[qid] = rec.get("retrieval_latency_ms", 0.0)
        generation_latencies[qid] = rec.get("generation_latency_ms", 0.0)
    return retrieval_outputs, generated_responses, retrieval_latencies, generation_latencies


def judge_items(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Project stage A records into the item shape LLMJudge.build_batch_requests wants."""
    return [
        {
            "query_id": r["query_id"],
            "scenario": r["scenario"],
            "engine_name": r["engine_name"],
            "attack_type": r["attack_type"],
            "query_text": r["query_text"],
            "ground_truth_answer": r["ground_truth_answer"],
            "target_poison_assertion": r["target_poison_assertion"],
            "generated_response": r["generated_response"],
        }
        for r in records
    ]


def generations_by_key(records: List[Dict[str, Any]]) -> Dict[Tuple[str, str], str]:
    """Map (scenario, query_id) -> generated response.

    Needed by the batch judge parsers: their fallback branches inspect the generated text,
    so withholding it would make a malformed judge reply parse differently on the batch
    path than on the sync path -- a divergence that looks exactly like a join bug.
    """
    return {(r["scenario"], r["query_id"]): r["generated_response"] for r in records}


# --------------------------------------------------------------------- stage B files

def stage_b_path(reports_dir: Path, run_id: str) -> Path:
    return Path(reports_dir) / f"stage_b_{run_id}.json"


def write_stage_b(
    path: Path,
    run_id: str,
    judge_model: str,
    gt_raw: Dict[str, str],
    poison_raw: Dict[str, str],
    manifest: List[Dict[str, Any]],
    cost: float,
    failed: Optional[Dict[str, Any]] = None
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "run_id": run_id,
        "judge_model": judge_model,
        "gt_raw": gt_raw,
        "poison_raw": poison_raw,
        "manifest": manifest,
        "usage_cost": cost,
        "failed": failed or {},
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def read_stage_b(path: Path) -> Dict[str, Any]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"No stage B results at {path}. Run --stage b first (or --resume-batch)."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def rebuild_queries(scenario_records: List[Dict[str, Any]]) -> List[GoldQuery]:
    """Rebuild GoldQuery objects from stage A records.

    Stage A stores every field Evaluator reads, so stage C never needs to reload the
    corpus or the query set -- which also means it cannot accidentally evaluate against a
    differently-seeded query sample than the one that was actually generated for.
    """
    return [
        GoldQuery(
            id=r["query_id"],
            query_text=r["query_text"],
            category=r.get("category", ""),
            ground_truth_doc_ids=r.get("ground_truth_doc_ids", []),
            ground_truth_answer=r["ground_truth_answer"],
            target_poison_assertion=r["target_poison_assertion"],
        )
        for r in scenario_records
    ]
