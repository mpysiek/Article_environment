"""OpenRouter Batch API client.

Used for the judge stage only. The judge is the one part of a benchmark run that nothing
downstream waits on, so it can absorb the Batch API's 24h completion window in exchange
for roughly half the per-token price.

Deliberately built on urllib rather than httpx: batch traffic is a handful of large
submissions plus a slow poll loop, so there is nothing to gain from async, and staying on
the standard library matches src/llm/openrouter_client.py and adds no dependency.
"""

import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Iterator

from src.config import config

TERMINAL_STATUSES = {"completed", "failed", "expired", "cancelled"}


class BatchSubmissionError(RuntimeError):
    """Raised when a batch cannot be submitted or reaches a non-completed terminal state."""


class OpenRouterBatchClient:
    """Submit, poll and collect OpenRouter batches, persisting state so a run can resume."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        state_dir: Optional[Path] = None,
        timeout: int = 300
    ):
        self.api_key = api_key or config.OPENROUTER_API_KEY
        self.base_url = (base_url or config.BATCH_BASE_URL).rstrip("/")
        self.state_dir = Path(state_dir) if state_dir else config.REPORTS_DIR
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout

    # ------------------------------------------------------------------ transport

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/rag-poisoning-benchmark",
            "X-Title": "RAG-Poisoning-Benchmark-Batch",
        }

    @staticmethod
    def build_payload(endpoint: str, model: str, requests: List[Dict[str, Any]]) -> str:
        """Serialize a batch body with `endpoint` and `model` ahead of `requests`.

        The API stream-parses the body so it can accept very large `requests` arrays without
        buffering, and returns 400 if `requests` is serialized first. Python dicts preserve
        insertion order and json.dumps follows it, so building the dict in this order is
        what guarantees the wire format. tests/test_batch_client.py locks this down.
        """
        if not requests:
            raise ValueError("A batch must contain at least one request.")
        seen = set()
        for item in requests:
            cid = item.get("custom_id")
            if not cid:
                raise ValueError(f"Every request needs a custom_id: {item!r}")
            if cid in seen:
                raise ValueError(f"Duplicate custom_id within one batch: {cid}")
            seen.add(cid)
        body = {"endpoint": endpoint, "model": model, "requests": requests}
        return json.dumps(body, ensure_ascii=False)

    def _request(self, method: str, path: str, body: Optional[str] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = body.encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            raise BatchSubmissionError(f"{method} {path} -> HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise BatchSubmissionError(f"{method} {path} -> transport error: {e.reason}") from e

    # ------------------------------------------------------------------ chunking

    @staticmethod
    def chunk(requests: List[Dict[str, Any]], size: Optional[int] = None) -> Iterator[List[Dict[str, Any]]]:
        """Split requests into submission-sized paczki."""
        size = size or config.BATCH_CHUNK_SIZE
        for i in range(0, len(requests), size):
            yield requests[i:i + size]

    # ------------------------------------------------------------------ lifecycle

    def submit(self, endpoint: str, model: str, requests: List[Dict[str, Any]]) -> str:
        payload = self.build_payload(endpoint, model, requests)
        result = self._request("POST", "/batches", payload)
        batch_id = result.get("id")
        if not batch_id:
            raise BatchSubmissionError(f"Submission returned no batch id: {result!r}")
        return batch_id

    def submit_all(
        self,
        endpoint: str,
        model: str,
        requests: List[Dict[str, Any]],
        chunk_size: Optional[int] = None
    ) -> List[str]:
        """Submit every chunk up front so they all share one 24h completion window."""
        return [
            self.submit(endpoint, model, part)
            for part in self.chunk(requests, chunk_size)
        ]

    def poll(self, batch_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/batches/{batch_id}")

    def wait_for_terminal(
        self,
        batch_ids: List[str],
        poll_interval: Optional[int] = None,
        on_progress=None
    ) -> List[Dict[str, Any]]:
        """Poll until every batch reaches a terminal status. Returns the final batch objects."""
        interval = poll_interval or config.BATCH_POLL_INTERVAL
        pending = list(batch_ids)
        done: Dict[str, Dict[str, Any]] = {}
        while pending:
            still_pending = []
            for bid in pending:
                batch = self.poll(bid)
                if batch.get("status") in TERMINAL_STATUSES:
                    done[bid] = batch
                else:
                    still_pending.append(bid)
            if on_progress:
                on_progress(done, still_pending)
            pending = still_pending
            if pending:
                time.sleep(interval)
        return [done[bid] for bid in batch_ids]

    # ------------------------------------------------------------------ results

    @staticmethod
    def collect(batches: List[Dict[str, Any]]) -> Tuple[Dict[str, str], Dict[str, Any], float]:
        """Split batch results into successes and failures.

        Returns (ok, failed, cost) where `ok` maps custom_id -> assistant message content,
        `failed` maps custom_id -> the error object, and `cost` is the summed usage.cost
        reported by the API. That reported cost is the source of truth for what a run
        actually spent -- the per-million rates in CROSS_PROVIDER_TIERS are only an estimate.
        """
        ok: Dict[str, str] = {}
        failed: Dict[str, Any] = {}
        cost = 0.0

        for batch in batches:
            usage = batch.get("usage") or {}
            if usage.get("cost") is not None:
                cost += float(usage["cost"])

            status = batch.get("status")
            if status != "completed":
                # A batch that failed, expired or was cancelled carries results = null.
                # Surface it rather than silently returning fewer verdicts than requested.
                raise BatchSubmissionError(
                    f"Batch {batch.get('id')} ended as '{status}': {batch.get('error')!r}"
                )

            for item in batch.get("results") or []:
                cid = item.get("custom_id")
                error = item.get("error")
                response = item.get("response")
                if error is not None or response is None:
                    failed[cid] = error or {"message": "missing response"}
                    continue
                try:
                    content = response["body"]["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError):
                    failed[cid] = {"message": f"unexpected response shape: {response!r}"[:300]}
                    continue
                ok[cid] = (content or "").strip()

        return ok, failed, cost

    # ------------------------------------------------------------------ persistence

    def state_path(self, run_id: str, stage: str) -> Path:
        return self.state_dir / f"batch_state_{stage}_{run_id}.json"

    def save_state(self, run_id: str, stage: str, batch_ids: List[str], model: str,
                   endpoint: str, extra: Optional[Dict[str, Any]] = None) -> Path:
        """Persist batch ids immediately after submission.

        Without this, a Ctrl+C between submit and collect throws away work that has already
        been paid for and cannot be re-fetched by any other means.
        """
        path = self.state_path(run_id, stage)
        payload = {
            "run_id": run_id,
            "stage": stage,
            "batch_ids": batch_ids,
            "model": model,
            "endpoint": endpoint,
            "submitted_at": time.time(),
        }
        if extra:
            payload.update(extra)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def load_state(self, run_id: str, stage: str) -> Dict[str, Any]:
        path = self.state_path(run_id, stage)
        if not path.exists():
            raise FileNotFoundError(f"No saved batch state at {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def save_raw_results(self, run_id: str, stage: str, batches: List[Dict[str, Any]]) -> Path:
        """Keep a local copy: OpenRouter deletes batch artifacts 30 days after creation."""
        path = self.state_dir / f"batch_raw_{stage}_{run_id}.json"
        path.write_text(json.dumps(batches, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    # ------------------------------------------------------------------ orchestration

    def run_batches(
        self,
        endpoint: str,
        model: str,
        requests: List[Dict[str, Any]],
        run_id: str,
        stage: str,
        poll_interval: Optional[int] = None,
        on_progress=None,
        max_retry_rounds: Optional[int] = None
    ) -> Tuple[Dict[str, str], Dict[str, Any], float]:
        """Submit, wait, collect, and resubmit whatever came back with an error.

        Per-item failures are re-queued as a smaller batch instead of aborting the run.
        Anything still failing after the retry rounds is returned in `failed` and must be
        reported as missing -- never silently defaulted, which would bias the metrics.
        """
        rounds = max_retry_rounds if max_retry_rounds is not None else config.BATCH_MAX_RETRY_ROUNDS
        by_id = {r["custom_id"]: r for r in requests}

        batch_ids = self.submit_all(endpoint, model, requests)
        self.save_state(run_id, stage, batch_ids, model, endpoint,
                        {"request_count": len(requests)})
        batches = self.wait_for_terminal(batch_ids, poll_interval, on_progress)
        self.save_raw_results(run_id, stage, batches)
        ok, failed, cost = self.collect(batches)

        for attempt in range(rounds):
            if not failed:
                break
            retry_requests = [by_id[cid] for cid in failed if cid in by_id]
            if not retry_requests:
                break
            retry_ids = self.submit_all(endpoint, model, retry_requests)
            self.save_state(run_id, f"{stage}_retry{attempt + 1}", retry_ids, model, endpoint,
                            {"request_count": len(retry_requests)})
            retry_batches = self.wait_for_terminal(retry_ids, poll_interval, on_progress)
            self.save_raw_results(run_id, f"{stage}_retry{attempt + 1}", retry_batches)
            retry_ok, failed, retry_cost = self.collect(retry_batches)
            ok.update(retry_ok)
            cost += retry_cost

        return ok, failed, cost

    def resume(
        self,
        run_id: str,
        stage: str,
        poll_interval: Optional[int] = None,
        on_progress=None
    ) -> Tuple[Dict[str, str], Dict[str, Any], float]:
        """Re-enter the poll loop for batches this run already submitted."""
        state = self.load_state(run_id, stage)
        batches = self.wait_for_terminal(state["batch_ids"], poll_interval, on_progress)
        self.save_raw_results(run_id, stage, batches)
        return self.collect(batches)
