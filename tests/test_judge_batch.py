"""Tests for the judge's batch mode.

The point of these is that the batch path must be a pure transport change: same prompts,
same parsers, same verdicts. Anything else silently changes what the benchmark measures.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import config
from src.evaluation.llm_judge import LLMJudge, JudgeVerdict


def _item(qid, scenario, response="The CVE is a use-after-free.", query="What is CVE-1?"):
    return {
        "query_id": qid,
        "scenario": scenario,
        "engine_name": "Hybrid-Reranker",
        "attack_type": "hybrid",
        "query_text": query,
        "ground_truth_answer": "It is a use-after-free.",
        "target_poison_assertion": "It is harmless.",
        "generated_response": response,
    }


@pytest.fixture
def judge():
    # Avoid the eager client construction in __init__ touching config/network.
    return LLMJudge(client=object(), async_client=object(), model="test-model")


class TestBuildBatchRequests:
    def test_custom_ids_are_unique(self, judge):
        items = [_item(f"q{i}", "Poisoned Hybrid", response=f"resp {i}") for i in range(50)]
        requests, _ = judge.build_batch_requests(items, "gt")
        ids = [r["custom_id"] for r in requests]
        assert len(ids) == len(set(ids)) == 50

    def test_body_omits_model(self, judge):
        """model is inherited from the batch level; a mismatch is rejected at submission."""
        requests, _ = judge.build_batch_requests([_item("q1", "s")], "poison")
        assert "model" not in requests[0]["body"]

    def test_body_uses_judge_max_tokens_and_json_mode(self, judge):
        requests, _ = judge.build_batch_requests([_item("q1", "s")], "gt")
        body = requests[0]["body"]
        assert body["max_tokens"] == config.JUDGE_MAX_TOKENS
        assert body["temperature"] == 0.0
        if config.JUDGE_JSON_MODE:
            assert body["response_format"] == {"type": "json_object"}

    def test_prompts_match_the_sync_builders_exactly(self, judge):
        item = _item("q1", "s")
        requests, _ = judge.build_batch_requests([item], "gt")
        expected = judge._build_gt_retention_messages(
            item["query_text"], item["ground_truth_answer"], item["generated_response"]
        )
        assert requests[0]["body"]["messages"] == expected

    def test_identical_prompts_are_sent_once_but_both_join(self, judge):
        """Two scenarios that produced the same generation are the same measurement."""
        items = [_item("q1", "Scenario A"), _item("q1", "Scenario B")]
        requests, manifest = judge.build_batch_requests(items, "gt")
        assert len(requests) == 1
        assert len(manifest) == 2
        assert {m["scenario"] for m in manifest} == {"Scenario A", "Scenario B"}
        assert {m["custom_id"] for m in manifest} == {requests[0]["custom_id"]}

    def test_differing_generations_are_not_deduplicated(self, judge):
        items = [_item("q1", "A", response="one"), _item("q1", "B", response="two")]
        requests, _ = judge.build_batch_requests(items, "gt")
        assert len(requests) == 2

    def test_rejects_unknown_kind(self, judge):
        with pytest.raises(ValueError, match="kind"):
            judge.build_batch_requests([_item("q1", "s")], "bogus")


class TestVerdictsFromBatch:
    def _fixture(self, judge, items):
        gt_reqs, gt_man = judge.build_batch_requests(items, "gt")
        ps_reqs, ps_man = judge.build_batch_requests(items, "poison")
        return gt_reqs, ps_reqs, gt_man + ps_man

    def test_reconstructs_the_same_verdict_as_the_sync_parsers(self, judge):
        items = [_item("q1", "Poisoned Hybrid")]
        gt_reqs, ps_reqs, manifest = self._fixture(judge, items)

        gt_body = '{"is_ground_truth_retained": true, "reasoning": "matches"}'
        ps_body = ('{"is_poison_adopted": true, "detected_conflict": false, '
                   '"adoption_severity": "full", "reasoning": "repeats it"}')

        verdicts, missing = judge.verdicts_from_batch(
            {gt_reqs[0]["custom_id"]: gt_body},
            {ps_reqs[0]["custom_id"]: ps_body},
            manifest,
        )
        assert missing == []
        v = verdicts[("Poisoned Hybrid", "q1")]
        assert isinstance(v, JudgeVerdict)
        assert v.is_ground_truth_retained is True
        assert v.is_poison_adopted is True
        assert v.adoption_severity == "full"
        assert "matches" in v.reasoning and "repeats it" in v.reasoning

    def test_deduplicated_prompt_fans_back_out_to_every_scenario(self, judge):
        items = [_item("q1", "A"), _item("q1", "B")]
        gt_reqs, ps_reqs, manifest = self._fixture(judge, items)
        verdicts, missing = judge.verdicts_from_batch(
            {gt_reqs[0]["custom_id"]: '{"is_ground_truth_retained": false, "reasoning": "no"}'},
            {ps_reqs[0]["custom_id"]: '{"is_poison_adopted": true, "reasoning": "yes"}'},
            manifest,
        )
        assert missing == []
        assert set(verdicts) == {("A", "q1"), ("B", "q1")}
        assert all(v.is_poison_adopted for v in verdicts.values())

    def test_missing_half_is_reported_not_defaulted(self, judge):
        """A dropped judge answer must not become a 'clean' verdict."""
        items = [_item("q1", "A")]
        gt_reqs, ps_reqs, manifest = self._fixture(judge, items)
        verdicts, missing = judge.verdicts_from_batch(
            {gt_reqs[0]["custom_id"]: '{"is_ground_truth_retained": true, "reasoning": "ok"}'},
            {},  # poison answer never came back
            manifest,
        )
        assert verdicts == {}
        assert missing == [("A", "q1")]

    def test_all_missing_reports_every_key(self, judge):
        items = [_item("q1", "A"), _item("q2", "A", response="other")]
        _, _, manifest = self._fixture(judge, items)
        verdicts, missing = judge.verdicts_from_batch({}, {}, manifest)
        assert verdicts == {}
        assert sorted(missing) == [("A", "q1"), ("A", "q2")]
