"""Tests for the persistent embedding cache.

Requires the retrieval dependencies (numpy, faiss, sentence-transformers) to be installed.
The cache is a correctness risk, not just a speed feature: a cache keyed without the model
name would hand vectors from one model to another and quietly change every retrieval
metric in the benchmark.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("faiss")
pytest.importorskip("sentence_transformers")

from src.config import config
from src.corpus.dataset import CTIDocument
from src.engines.retrievers import DenseFAISSRetriever


def _docs(n=8):
    return [
        CTIDocument(id=f"CVE-2024-{i}", title=f"Vuln {i}",
                    text=f"A use-after-free in component {i}.", doc_type="cve")
        for i in range(n)
    ]


@pytest.fixture(scope="module")
def model_name():
    return config.DENSE_MODEL_NAME


class TestCacheKeys:
    def test_key_changes_with_any_field(self):
        a = CTIDocument(id="X", title="T", text="body", doc_type="cve")
        assert DenseFAISSRetriever._cache_key(a) == DenseFAISSRetriever._cache_key(
            CTIDocument(id="X", title="T", text="body", doc_type="cve"))
        for changed in (
            CTIDocument(id="Y", title="T", text="body", doc_type="cve"),
            CTIDocument(id="X", title="U", text="body", doc_type="cve"),
            CTIDocument(id="X", title="T", text="other", doc_type="cve"),
        ):
            assert DenseFAISSRetriever._cache_key(a) != DenseFAISSRetriever._cache_key(changed)

    def test_slug_is_filesystem_safe(self, model_name):
        slug = DenseFAISSRetriever(model_name, persist_cache=False).model_slug()
        assert "/" not in slug and " " not in slug


class TestPersistence:
    def test_second_instance_encodes_nothing(self, tmp_path, model_name):
        docs = _docs()
        first = DenseFAISSRetriever(model_name, cache_dir=tmp_path / "c")
        first.build_index(docs)
        assert first.encoded_count == len(docs)
        first.flush_cache()

        second = DenseFAISSRetriever(model_name, cache_dir=tmp_path / "c")
        second.build_index(docs)
        assert second.encoded_count == 0
        assert second.cache_hits == len(docs)

    def test_counters_reset_per_build(self, tmp_path, model_name):
        r = DenseFAISSRetriever(model_name, cache_dir=tmp_path / "c")
        docs = _docs()
        r.build_index(docs)
        r.build_index(docs)
        # Second build over the same docs: all hits, nothing encoded, no carry-over.
        assert r.encoded_count == 0
        assert r.cache_hits == len(docs)
        assert r.cache_misses == 0

    def test_new_documents_encode_only_the_new_ones(self, tmp_path, model_name):
        r = DenseFAISSRetriever(model_name, cache_dir=tmp_path / "c")
        docs = _docs(8)
        r.build_index(docs)
        extra = docs + [CTIDocument(id="POISON-1", title="Benign", text="It is harmless.",
                                    doc_type="cve", is_poisoned=True)]
        r.build_index(extra)
        assert r.encoded_count == 1

    def test_a_different_model_slug_does_not_read_the_cache(self, tmp_path, model_name):
        """The cache path must be namespaced by model, or a swap returns stale vectors."""
        docs = _docs()
        a = DenseFAISSRetriever(model_name, cache_dir=tmp_path / "modelA")
        a.build_index(docs)
        a.flush_cache()

        b = DenseFAISSRetriever(model_name, cache_dir=tmp_path / "modelB")
        b.build_index(docs)
        assert b.encoded_count == len(docs)

    def test_default_cache_dir_contains_the_model_slug(self, model_name):
        r = DenseFAISSRetriever(model_name, persist_cache=False)
        assert r.model_slug() in str(r.cache_dir)
        assert str(config.EMBED_CACHE_DIR) in str(r.cache_dir)

    def test_corrupt_cache_is_survivable(self, tmp_path, model_name):
        cache = tmp_path / "c"
        cache.mkdir()
        (cache / DenseFAISSRetriever.CACHE_KEYS_FILE).write_text("not json")
        (cache / DenseFAISSRetriever.CACHE_VECTORS_FILE).write_bytes(b"garbage")
        r = DenseFAISSRetriever(model_name, cache_dir=cache)
        r.build_index(_docs())          # must re-encode rather than raise
        assert r.encoded_count == len(_docs())


class TestQueryPrefix:
    def test_prefix_is_applied_to_queries_only(self, tmp_path, model_name):
        """Documents are encoded raw; only the query carries the instruction prefix.

        Asserted on content rather than call order: sentence-transformers is free to change
        how many times it calls encode() internally.
        """
        r = DenseFAISSRetriever(model_name, query_prefix="PREFIX: ", cache_dir=tmp_path / "c")
        seen = []
        original = r.model.encode

        def spy(texts, **kwargs):
            seen.append(list(texts))
            return original(texts, **kwargs)

        r.model.encode = spy
        try:
            r.build_index(_docs(2))
            r.retrieve("what is this")
        finally:
            r.model.encode = original

        prefixed = [t for batch in seen for t in batch if t.startswith("PREFIX: ")]
        assert prefixed == ["PREFIX: what is this"]
        # No document text is ever prefixed.
        assert not any(t.startswith("PREFIX: ") and "use-after-free" in t
                       for batch in seen for t in batch)
