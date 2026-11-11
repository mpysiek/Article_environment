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

    POISON_TAG: str = ""  # Empty by default for realistic injection without artificial tags
    QUERY_ECHO: bool = False  # Reference mode: distinct vectors without verbatim query echo

config = BenchmarkConfig()

#: The run described in manuscripts v2 and v3. Nothing may be written there.
ARCHIVE_REPORTS_DIR = BASE_DIR / "outputs" / "reports" / "v2"


def refuse_archive_dir(path) -> Path:
    """Returns `path`, or raises if a script is about to write into the archived v2 run."""
    resolved = Path(path).resolve()
    if resolved == ARCHIVE_REPORTS_DIR.resolve():
        raise SystemExit(
            f"Odmowa zapisu do {ARCHIVE_REPORTS_DIR}: to archiwum przebiegu v2. "
            f"Podaj --out-dir albo skopiuj folder i wskaż kopię."
        )
    return Path(path)
