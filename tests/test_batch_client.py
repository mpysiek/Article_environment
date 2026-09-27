"""Tests for the OpenRouter Batch API client.

These deliberately avoid the network: they lock down the wire format and the join/failure
semantics, which are the parts that are expensive to get wrong (a malformed body costs a
400 after the generation stage has already run and been paid for).
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.llm.batch_client import OpenRouterBatchClient, BatchSubmissionError


def _req(cid, text="hi"):
    return {"custom_id": cid, "body": {"messages": [{"role": "user", "content": text}]}}


class TestPayloadOrdering:
    def test_endpoint_and_model_serialized_before_requests(self):
        """The API stream-parses the body and returns 400 if `requests` comes first."""
        raw = OpenRouterBatchClient.build_payload(
            "/v1/chat/completions", "meta-llama/llama-3.3-70b-instruct", [_req("gt000000")]
        )
        assert raw.index('"endpoint"') < raw.index('"requests"')
        assert raw.index('"model"') < raw.index('"requests"')

    def test_payload_roundtrips(self):
        raw = OpenRouterBatchClient.build_payload("/v1/chat/completions", "m", [_req("a")])
        body = json.loads(raw)
        assert body["endpoint"] == "/v1/chat/completions"
        assert body["model"] == "m"
        assert len(body["requests"]) == 1

    def test_rejects_empty_batch(self):
        with pytest.raises(ValueError):
            OpenRouterBatchClient.build_payload("/v1/chat/completions", "m", [])

    def test_rejects_duplicate_custom_id(self):
        with pytest.raises(ValueError, match="Duplicate custom_id"):
            OpenRouterBatchClient.build_payload(
                "/v1/chat/completions", "m", [_req("dup"), _req("dup")]
            )

    def test_rejects_missing_custom_id(self):
        with pytest.raises(ValueError, match="custom_id"):
            OpenRouterBatchClient.build_payload(
                "/v1/chat/completions", "m", [{"body": {"messages": []}}]
            )


class TestChunking:
    def test_splits_into_full_chunks_and_remainder(self):
        reqs = [_req(f"r{i:04d}") for i in range(2500)]
        chunks = list(OpenRouterBatchClient.chunk(reqs, size=1000))
        assert [len(c) for c in chunks] == [1000, 1000, 500]

    def test_every_request_appears_exactly_once(self):
        reqs = [_req(f"r{i:04d}") for i in range(250)]
        flat = [r for c in OpenRouterBatchClient.chunk(reqs, size=64) for r in c]
        assert flat == reqs


def _batch(results, status="completed", cost=None):
    usage = {"cost": cost} if cost is not None else None
    return {"id": "batch_1", "status": status, "usage": usage, "results": results}


def _ok_result(cid, content):
    return {
        "custom_id": cid,
        "response": {"status_code": 200, "body": {"choices": [{"message": {"content": content}}]}},
        "error": None,
    }


class TestCollect:
    def test_extracts_content_and_sums_cost(self):
        ok, failed, cost = OpenRouterBatchClient.collect([
            _batch([_ok_result("gt000000", ' {"a": 1} ')], cost=0.5),
            _batch([_ok_result("gt000001", "x")], cost=0.25),
        ])
        assert ok == {"gt000000": '{"a": 1}', "gt000001": "x"}
        assert failed == {}
        assert cost == pytest.approx(0.75)

    def test_per_item_error_goes_to_failed_not_ok(self):
        ok, failed, _ = OpenRouterBatchClient.collect([
            _batch([_ok_result("a", "fine"),
                    {"custom_id": "b", "response": None, "error": {"message": "boom"}}])
        ])
        assert list(ok) == ["a"]
        assert failed["b"]["message"] == "boom"

    def test_unexpected_response_shape_is_a_failure_not_a_crash(self):
        ok, failed, _ = OpenRouterBatchClient.collect([
            _batch([{"custom_id": "c", "response": {"body": {}}, "error": None}])
        ])
        assert ok == {}
        assert "c" in failed

    @pytest.mark.parametrize("status", ["failed", "expired", "cancelled"])
    def test_non_completed_batch_raises(self, status):
        with pytest.raises(BatchSubmissionError, match=status):
            OpenRouterBatchClient.collect([_batch(None, status=status)])


class TestStatePersistence:
    def test_state_roundtrips(self, tmp_path):
        client = OpenRouterBatchClient(api_key="k", state_dir=tmp_path)
        client.save_state("run7", "judge_gt", ["b1", "b2"], "m", "/v1/chat/completions")
        state = client.load_state("run7", "judge_gt")
        assert state["batch_ids"] == ["b1", "b2"]
        assert state["model"] == "m"

    def test_missing_state_is_explicit(self, tmp_path):
        client = OpenRouterBatchClient(api_key="k", state_dir=tmp_path)
        with pytest.raises(FileNotFoundError):
            client.load_state("nope", "judge_gt")
