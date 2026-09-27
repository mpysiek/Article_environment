import os
from pathlib import Path
from dataclasses import dataclass

BASE_DIR = Path(__file__).resolve().parent.parent

@dataclass
class BenchmarkConfig:
    ROOT_DIR: Path = BASE_DIR
    DATA_DIR: Path = BASE_DIR / "data"
    OUTPUT_DIR: Path = BASE_DIR / "outputs"
    REPORTS_DIR: Path = BASE_DIR / "outputs" / "reports"

    # Retrieval Models.
    # bge-small-en-v1.5 keeps the 384-dim vector width of all-MiniLM-L6-v2 (so the FAISS
    # index is unchanged) but accepts 512 tokens instead of 256. Under MiniLM, 2180 of the
    # 24000 real CTI documents were silently truncated for dense retrieval while BM25 saw
    # them in full -- an asymmetry between the very engines this benchmark compares.
    DENSE_MODEL_NAME: str = "BAAI/bge-small-en-v1.5"
    RERANKER_MODEL_NAME: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"

    # BGE models expect this instruction on the query side only; documents are encoded raw.
    # Leave empty for models that need no prefix (e.g. all-MiniLM-L6-v2).
    DENSE_QUERY_PREFIX: str = "Represent this sentence for searching relevant passages: "

    RERANKER_BATCH_SIZE: int = 64
    EMBED_CACHE_DIR: Path = BASE_DIR / "data" / "cache" / "embeddings"

    TOP_K: int = 5
    HYBRID_ALPHA: float = 0.5
    RRF_K: int = 60

    # OpenRouter LLM Configuration.
    # Supplied via the OPENROUTER_API_KEY environment variable; never hardcode a key here.
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    GENERATOR_MODEL: str = "meta-llama/llama-3.3-70b-instruct"
    JUDGE_MODEL: str = "meta-llama/llama-3.3-70b-instruct"
    LLM_TEMPERATURE: float = 0.0
    LLM_MAX_TOKENS: int = 800
    LLM_TIMEOUT: int = 45
    LLM_MAX_RETRIES: int = 4

    # The judge emits a small JSON object (~60-70 tokens), but `reasoning` is free text.
    # Too tight a cap truncates the JSON, which fails parsing and falls back to defaults
    # that bias the metrics toward "clean" -- measure before tightening this.
    JUDGE_MAX_TOKENS: int = 300
    JUDGE_JSON_MODE: bool = True

    # --- Batch API (judge stage only; generation stays synchronous) ---
    BATCH_BASE_URL: str = "https://openrouter.ai/api/beta"
    BATCH_COMPLETION_WINDOW: str = "24h"
    # Requests per submitted batch. The API documents no maximum, so this is a defensive
    # default that must be confirmed by the Krok 0 smoke test before a full run.
    BATCH_CHUNK_SIZE: int = 2000
    # Below this many judge requests the queue overhead outweighs the 50% discount,
    # so the run falls back to the synchronous judge path.
    BATCH_MIN_REQUESTS: int = 500
    BATCH_POLL_INTERVAL: int = 60
    BATCH_MAX_RETRY_ROUNDS: int = 2

    POISON_TAG: str = ""  # Empty by default for realistic injection without artificial tags
    QUERY_ECHO: bool = False  # Reference mode: distinct vectors without verbatim query echo

config = BenchmarkConfig()

CROSS_PROVIDER_TIERS = {
    "mid": {
        "generator_model": "google/gemini-3.7-flash",
        "judge_model": "anthropic/claude-haiku-4.5",
        "name": "Mid-Tier (Gemini 3.7 Flash + Claude Haiku 4.5)",
        "generator_cost_per_m_in": 0.75,
        "generator_cost_per_m_out": 3.75,
        "judge_cost_per_m_in": 1.00,
        "judge_cost_per_m_out": 5.00
    },
    "low": {
        "generator_model": "google/gemini-2.5-flash-lite",
        "judge_model": "anthropic/claude-3-haiku",
        "name": "Low-Tier (Gemini 2.5 Flash-Lite + Claude 3 Haiku)",
        "generator_cost_per_m_in": 0.10,
        "generator_cost_per_m_out": 0.40,
        "judge_cost_per_m_in": 0.25,
        "judge_cost_per_m_out": 1.25
    },
    "baseline": {
        "generator_model": "meta-llama/llama-3.3-70b-instruct",
        "judge_model": "meta-llama/llama-3.3-70b-instruct",
        "name": "Baseline (Llama 3.3 70B)",
        "generator_cost_per_m_in": 0.71,
        "generator_cost_per_m_out": 0.71,
        "judge_cost_per_m_in": 0.71,
        "judge_cost_per_m_out": 0.71
    }
}
