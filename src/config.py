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

    # Retrieval Models
    DENSE_MODEL_NAME: str = "sentence-transformers/all-MiniLM-L6-v2"
    RERANKER_MODEL_NAME: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"

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

    POISON_TAG: str = ""  # Empty by default for realistic injection without artificial tags

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
