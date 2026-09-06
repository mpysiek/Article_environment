import json
import time
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional
from src.config import config

class OpenRouterClient:
    """Client for calling OpenRouter API with robust retry and error handling."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        self.api_key = api_key or config.OPENROUTER_API_KEY
        self.base_url = (base_url or config.OPENROUTER_BASE_URL).rstrip("/")

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = config.LLM_TEMPERATURE,
        max_tokens: int = config.LLM_MAX_TOKENS,
        timeout: int = config.LLM_TIMEOUT,
        max_retries: int = config.LLM_MAX_RETRIES
    ) -> str:
        model = model or config.GENERATOR_MODEL
        url = f"{self.base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/rag-poisoning-benchmark",
            "X-Title": "RAG-Poisoning-CTI-Benchmark"
        }

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        data = json.dumps(payload).encode("utf-8")

        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    body = json.loads(response.read().decode("utf-8"))
                    choices = body.get("choices", [])
                    if choices and "message" in choices[0]:
                        return choices[0]["message"].get("content", "").strip()
                    raise ValueError(f"Unexpected API response structure: {body}")

            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="ignore")
                last_error = f"HTTP {e.code}: {err_body}"
                # If rate-limited (429) or server error (500, 502, 503, 504), retry with backoff
                if e.code in [429, 500, 502, 503, 504] and attempt < max_retries:
                    sleep_time = (2 ** attempt) + 1
                    time.sleep(sleep_time)
                    continue
                break

            except Exception as e:
                last_error = str(e)
                if attempt < max_retries:
                    sleep_time = (2 ** attempt) + 0.5
                    time.sleep(sleep_time)
                    continue
                break

        raise RuntimeError(f"OpenRouter API call failed after {max_retries} attempts. Error: {last_error}")

