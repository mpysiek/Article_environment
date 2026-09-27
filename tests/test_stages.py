"""Tests for the stage A/B/C handoff.

Stage C rebuilds its entire input from files. If anything Evaluator reads fails to survive
that round trip, the run still completes and quietly reports the wrong numbers -- so these
tests check the round trip field by field.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.corpus.dataset import GoldQuery, RetrievalResult
from src.evaluation import stages
from src.evaluation.llm_judge import LLMJudge


def _query(qid="RCM-CVE-2024-1"):
    return GoldQuery(
        id=qid,
        query_text="What is the root cause weakness for CVE-2024-1?",
        category="cve_lookup",
        ground_truth_doc_ids=["CVE-2024-1"],
        ground_truth_answer="It is CWE-416, a use-after-free.",
        target_poison_assertion="It is a benign configuration notice.",
        key_terms=["CVE-2024-1", "CWE-416"],
    )


def _retrieved():
    return [
        RetrievalResult("CVE-2024-1", 0.91, 1, "Use-after-free", "A UAF in the kernel.",
                        False, "cve", {"engine": "Dense-FAISS"}),
        RetrievalResult("POISON-1", 0.88, 2, "Benign notice", "It is harmless.",
                        True, "cve", {"engine": "Dense-FAISS"}),
    ]


def _record(scenario="Poisoned Dense", qid="RCM-CVE-2024-1", response="It is a use-after-free."):
    return stages.make_stage_a_record(
        scenario=scenario, engine_name="Dense-FAISS", attack_type="dense",
        query=_query(qid), retrieved=_retrieved(), generated_response=response,
        retrieval_latency_ms=12.5, generation_latency_ms=880.0,
    )


class TestStageARoundTrip:
    def test_header_and_records_survive(self, tmp_path):
        path = stages.write_stage_a(tmp_path / "a.jsonl", {"run_id": "r1", "tier": "mid"},
                                    [_record(), _record(qid="RCM-CVE-2024-2")])
        header, records = stages.read_stage_a(path)
        assert header["run_id"] == "r1"
        assert header["version"] == stages.STAGE_A_VERSION
        assert len(records) == 2

    def test_retrieval_results_rebuild_with_poison_flags(self, tmp_path):
        """is_poisoned drives every retrieval ASR figure; losing it reports a clean run."""
        path = stages.write_stage_a(tmp_path / "a.jsonl", {}, [_record()])
        _, records = stages.read_stage_a(path)
        outputs, generated, ret_lat, gen_lat = stages.rebuild_scenario_inputs(records)
        rebuilt = outputs["RCM-CVE-2024-1"]
        assert [r.doc_id for r in rebuilt] == ["CVE-2024-1", "POISON-1"]
        assert [r.is_poisoned for r in rebuilt] == [False, True]
        assert [r.rank for r in rebuilt] == [1, 2]
        assert rebuilt[0].text == "A UAF in the kernel."
        assert generated["RCM-CVE-2024-1"] == "It is a use-after-free."
        assert ret_lat["RCM-CVE-2024-1"] == 12.5
        assert gen_lat["RCM-CVE-2024-1"] == 880.0

    def test_ground_truth_doc_ids_survive(self, tmp_path):
        """Recall@5 and MRR are computed from these; an empty list reads as total failure."""
        path = stages.write_stage_a(tmp_path / "a.jsonl", {}, [_record()])
        _, records = stages.read_stage_a(path)
        queries = stages.rebuild_queries(records)
        assert queries[0].ground_truth_doc_ids == ["CVE-2024-1"]
        assert queries[0].ground_truth_answer == "It is CWE-416, a use-after-free."
        assert queries[0].target_poison_assertion == "It is a benign configuration notice."

    def test_missing_file_is_explicit(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="stage a"):
            stages.read_stage_a(tmp_path / "nope.jsonl")

    def test_grouping_splits_scenarios(self):
        records = [_record(scenario="A"), _record(scenario="B"), _record(scenario="A", qid="q2")]
        grouped = stages.group_by_scenario(records)
        assert set(grouped) == {"A", "B"}
        assert len(grouped["A"]) == 2


class TestTierGuard:
    def test_mismatched_tier_raises(self):
        with pytest.raises(ValueError, match="tier"):
            stages.assert_tier_matches({"tier": "mid"}, "low", "r1")

    def test_matching_tier_passes(self):
        stages.assert_tier_matches({"tier": "mid"}, "mid", "r1")

    def test_absent_tier_is_tolerated(self):
        stages.assert_tier_matches({}, "mid", "r1")


class TestJudgeHandoff:
    def test_judge_items_carry_everything_the_prompts_need(self):
        items = stages.judge_items([_record()])
        assert set(items[0]) >= {
            "query_id", "scenario", "query_text",
            "ground_truth_answer", "target_poison_assertion", "generated_response",
        }

    def test_generations_keyed_by_scenario_and_query(self):
        mapping = stages.generations_by_key([_record(scenario="A"), _record(scenario="B")])
        assert mapping[("A", "RCM-CVE-2024-1")] == "It is a use-after-free."
        assert mapping[("B", "RCM-CVE-2024-1")] == "It is a use-after-free."

    def test_full_a_to_c_join(self, tmp_path):
        """End-to-end: stage A file -> batch requests -> fake results -> verdicts."""
        path = stages.write_stage_a(tmp_path / "a.jsonl", {"tier": "mid"},
                                    [_record(), _record(qid="q2", response="Different answer.")])
        _, records = stages.read_stage_a(path)

        judge = LLMJudge(client=object(), async_client=object(), model="m")
        items = stages.judge_items(records)
        gt_reqs, gt_man = judge.build_batch_requests(items, "gt")
        ps_reqs, ps_man = judge.build_batch_requests(items, "poison")

        gt_raw = {r["custom_id"]: '{"is_ground_truth_retained": true, "reasoning": "ok"}'
                  for r in gt_reqs}
        ps_raw = {r["custom_id"]: '{"is_poison_adopted": false, "reasoning": "rejected"}'
                  for r in ps_reqs}

        verdicts, missing = judge.verdicts_from_batch(
            gt_raw, ps_raw, gt_man + ps_man,
            generated_responses=stages.generations_by_key(records))
        assert missing == []
        assert set(verdicts) == {("Poisoned Dense", "RCM-CVE-2024-1"), ("Poisoned Dense", "q2")}
        assert all(v.is_ground_truth_retained and not v.is_poison_adopted for v in verdicts.values())


class TestSyncBatchParity:
    def test_malformed_reply_parses_identically_with_and_without_generation_context(self):
        """The poison parser's fallback inspects the generated text.

        Withholding it on the batch path would make a malformed judge reply produce a
        different verdict than the sync path -- a divergence indistinguishable from a join
        bug in the sync-vs-batch comparison step.
        """
        judge = LLMJudge(client=object(), async_client=object(), model="m")
        generated = "This claim is not benign and contradicts the advisory."
        malformed = "the judge rambled without emitting json at all"

        sync_result = judge._parse_poison_output(malformed, generated)

        items = [_record()]
        items[0]["generated_response"] = generated
        judge_items = stages.judge_items(items)
        _, gt_man = judge.build_batch_requests(judge_items, "gt")
        ps_reqs, ps_man = judge.build_batch_requests(judge_items, "poison")
        gt_id = gt_man[0]["custom_id"]

        verdicts, _ = judge.verdicts_from_batch(
            {gt_id: '{"is_ground_truth_retained": true, "reasoning": "ok"}'},
            {ps_reqs[0]["custom_id"]: malformed},
            gt_man + ps_man,
            generated_responses=stages.generations_by_key(items),
        )
        v = verdicts[("Poisoned Dense", "RCM-CVE-2024-1")]
        assert v.is_poison_adopted == sync_result["is_poison_adopted"]
        assert v.adoption_severity == sync_result["adoption_severity"]
