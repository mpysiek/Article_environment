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

    async def chat_async(
        self,
        client: httpx.AsyncClient,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = config.LLM_TEMPERATURE,
        max_tokens: int = config.LLM_MAX_TOKENS,
        timeout: int = config.LLM_TIMEOUT,
        max_retries: int = config.LLM_MAX_RETRIES
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

        async with self.semaphore:
            last_error = None
            for attempt in range(1, max_retries + 1):
                try:
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
                            sleep_time = (2 ** attempt) + 0.5 * (attempt)
                            await asyncio.sleep(sleep_time)
                            continue
                    
                    response.raise_for_status()

                except (httpx.RequestError, httpx.TimeoutException) as e:
                    last_error = str(e)
                    if attempt < max_retries:
                        sleep_time = (2 ** attempt) + 1.0
                        await asyncio.sleep(sleep_time)
                        continue
                except Exception as e:
                    last_error = str(e)
                    if attempt < max_retries:
                        await asyncio.sleep(2)
                        continue

            raise RuntimeError(f"OpenRouter Async API call failed after {max_retries} retries. Error: {last_error}")
