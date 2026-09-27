import asyncio
import json
import time
import httpx
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from src.config import config

class AsyncOpenRouterClient:
    """High-throughput asynchronous OpenRouter client with concurrency pooling, retry backoff, and checkpointing."""

    def __init__(
        self, 
        api_key: Optional[str] = None, 
        base_url: Optional[str] = None,
        concurrency: int = 15,
        checkpoint_file: Optional[Path] = None
    ):
        self.api_key = api_key or config.OPENROUTER_API_KEY
        self.base_url = (base_url or config.OPENROUTER_BASE_URL).rstrip("/")
        self.semaphore = asyncio.Semaphore(concurrency)
        self.checkpoint_file = checkpoint_file or (config.REPORTS_DIR / "checkpoint_traces.jsonl")
        self.checkpoint_file.parent.mkdir(parents=True, exist_ok=True)

    def append_checkpoint(self, record: Dict[str, Any]):
        """Append a trace record to the JSONL checkpoint file in real-time."""
        with open(self.checkpoint_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    @staticmethod
    def _backoff_seconds(response: "httpx.Response", attempt: int) -> float:
        """Honour a Retry-After header when the provider sends one, else exponential backoff."""
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                # Cap it so a hostile or mistaken header cannot stall the run for hours.
                return min(float(retry_after), 120.0)
            except ValueError:
                pass
        return (2 ** attempt) + 0.5 * attempt

    async def chat_async(
        self,
        client: httpx.AsyncClient,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = config.LLM_TEMPERATURE,
        max_tokens: int = config.LLM_MAX_TOKENS,
        timeout: int = config.LLM_TIMEOUT,
        max_retries: int = config.LLM_MAX_RETRIES,
        response_format: Optional[Dict[str, Any]] = None
    ) -> str:
        """Execute a single async chat completion call with semaphore concurrency and retry backoff."""
        model = model or config.GENERATOR_MODEL
        url = f"{self.base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/rag-poisoning-benchmark",
            "X-Title": "RAG-Poisoning-Enterprise-Benchmark"
        }

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        if response_format is not None:
            payload["response_format"] = response_format

        last_error = None
        for attempt in range(1, max_retries + 1):
            sleep_time = None
            try:
                # The semaphore is held only for the network call itself. Holding it across
                # the backoff sleep would let a 429 burst freeze every concurrency slot.
                async with self.semaphore:
                    response = await client.post(
                        url,
                        json=payload,
                        headers=headers,
                        timeout=timeout
                    )

                if response.status_code == 200:
                    body = response.json()
                    choices = body.get("choices", [])
                    if choices and "message" in choices[0]:
                        return choices[0]["message"].get("content", "").strip()
                    raise ValueError(f"Unexpected API response payload: {body}")

                # Rate-limiting or transient server errors -> backoff and retry
                if response.status_code in [429, 500, 502, 503, 504, 520, 524]:
                    last_error = f"HTTP {response.status_code}: {response.text}"
                    if attempt < max_retries:
                        sleep_time = self._backoff_seconds(response, attempt)
                    else:
                        break
                else:
                    # Non-retryable client errors (400 bad request, 401 bad key, 403, 404...).
                    # Retrying these burns the whole retry budget on every single call, so
                    # fail immediately -- matching OpenRouterClient's behaviour.
                    raise RuntimeError(
                        f"OpenRouter Async API returned non-retryable "
                        f"HTTP {response.status_code}: {response.text[:300]}"
                    )

            except (httpx.RequestError, httpx.TimeoutException, ValueError) as e:
                # Transport failures and malformed-but-200 payloads are both worth retrying.
                last_error = str(e)
                if attempt < max_retries:
                    sleep_time = (2 ** attempt) + 1.0
                else:
                    break

            if sleep_time is not None:
                await asyncio.sleep(sleep_time)

        raise RuntimeError(f"OpenRouter Async API call failed after {max_retries} retries. Error: {last_error}")
