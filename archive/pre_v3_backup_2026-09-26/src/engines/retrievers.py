import re
import math
import numpy as np
import networkx as nx
from typing import List, Dict, Any, Optional
from rank_bm25 import BM25Okapi
import faiss
from sentence_transformers import SentenceTransformer, CrossEncoder
import atexit
import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

from src.corpus.dataset import CTIDocument, RetrievalResult
from src.config import config

class BaseRetriever:
    def __init__(self, name: str):
        self.name = name
        self.documents: List[CTIDocument] = []

    def build_index(self, documents: List[CTIDocument]):
        raise NotImplementedError

    def retrieve(self, query: str, top_k: int = 5) -> List[RetrievalResult]:
        raise NotImplementedError

CTI_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of",
    "with", "by", "from", "up", "about", "into", "over", "after", "is", "are",
    "was", "were", "be", "being", "have", "has", "had", "do", "does", "did",
    "what", "which", "who", "whom", "this", "that", "these", "those", "am",
    "it", "its", "as", "if", "each", "how", "all", "any", "both", "few",
    "more", "most", "other", "some", "such", "no", "nor", "not", "only",
    "own", "same", "so", "than", "too", "very", "can", "will", "just",
    "should", "now", "also", "uses", "used", "using", "out", "new", "get",
    "got", "set", "one", "two", "see", "our", "their", "there", "then",
    "when", "where", "why", "here", "them", "they", "we", "you", "your",
    "my", "me", "he", "she", "his", "her", "him", "us"
}

class BM25Retriever(BaseRetriever):
    """Sparse lexical retrieval engine based on BM25 Okapi."""
    STOPWORDS = CTI_STOPWORDS

    def __init__(self):
        super().__init__("Sparse-BM25")
        self.bm25 = None
        self.corpus_tokens = []
        self._doc_token_cache: Dict[str, List[str]] = {}
        self._base_doc_ids: Optional[List[str]] = None
        self._base_corpus_tokens: Optional[List[List[str]]] = None
        self._base_bm25: Optional[BM25Okapi] = None
        self._base_doc_freqs: Optional[List[Dict[str, int]]] = None
        self._base_doc_len: Optional[List[int]] = None
        self._base_num_doc: int = 0
        self._base_corpus_size: int = 0
        self._base_nd: Optional[Dict[str, int]] = None

    def _tokenize(self, text: str) -> List[str]:
        text = text.lower()
        raw_tokens = re.findall(r'[a-zA-Z0-9_\-\.]+', text)
        clean_tokens = []
        for t in raw_tokens:
            stripped = t.strip(".")
            if stripped and stripped not in self.STOPWORDS:
                clean_tokens.append(stripped)
        return clean_tokens

    def _get_doc_tokens(self, doc: CTIDocument) -> List[str]:
        if not doc.is_poisoned and doc.id in self._doc_token_cache:
            return self._doc_token_cache[doc.id]
        tokens = self._tokenize(doc.id + " " + doc.title + " " + doc.text)
        if not doc.is_poisoned:
            self._doc_token_cache[doc.id] = tokens
        return tokens

    def build_index(self, documents: List[CTIDocument]):
        self.documents = list(documents)
        if not self.documents:
            self.bm25 = None
            self.corpus_tokens = []
            self._base_doc_ids = None
            self._base_corpus_tokens = None
            self._base_bm25 = None
            self._base_doc_freqs = None
            self._base_doc_len = None
            self._base_num_doc = 0
            self._base_corpus_size = 0
            self._base_nd = None
            return

        clean_docs = [d for d in self.documents if not d.is_poisoned]
        poison_docs = [d for d in self.documents if d.is_poisoned]

        # Fast incremental path: strictly verify self.documents starts with base clean documents
        # in identical order and that all subsequent documents are poisoned.
        is_clean_prefix = (
            self._base_bm25 is not None
            and self._base_doc_ids is not None
            and len(self.documents) >= self._base_corpus_size
            and [d.id for d in self.documents[:self._base_corpus_size]] == self._base_doc_ids
            and not any(d.is_poisoned for d in self.documents[:self._base_corpus_size])
            and all(d.is_poisoned for d in self.documents[self._base_corpus_size:])
        )

        if is_clean_prefix:
            if not poison_docs:
                self.bm25 = self._base_bm25
                self.corpus_tokens = self._base_corpus_tokens
                return

            # Incremental update for poison documents
            poison_tokens = [self._get_doc_tokens(doc) for doc in poison_docs]
            safe_poison_tokens = [tokens if len(tokens) > 0 else ["__empty__"] for tokens in poison_tokens]
            self.corpus_tokens = self._base_corpus_tokens + poison_tokens

            p_doc_lens = [len(toks) for toks in safe_poison_tokens]
            p_freqs = []
            nd_delta = {}
            for toks in safe_poison_tokens:
                freq = {}
                for w in toks:
                    freq[w] = freq.get(w, 0) + 1
                p_freqs.append(freq)
                for w in freq:
                    nd_delta[w] = nd_delta.get(w, 0) + 1

            bm_inc = object.__new__(BM25Okapi)
            bm_inc.k1 = self._base_bm25.k1
            bm_inc.b = self._base_bm25.b
            bm_inc.epsilon = self._base_bm25.epsilon
            bm_inc.corpus_size = self._base_corpus_size + len(poison_docs)
            bm_inc.avgdl = (self._base_num_doc + sum(p_doc_lens)) / bm_inc.corpus_size
            bm_inc.doc_freqs = self._base_doc_freqs + p_freqs
            bm_inc.doc_len = self._base_doc_len + p_doc_lens
            bm_inc.tokenizer = None
            bm_inc.idf = {}

            nd = dict(self._base_nd)
            for w, cnt in nd_delta.items():
                nd[w] = nd.get(w, 0) + cnt
            bm_inc._calc_idf(nd)

            self.bm25 = bm_inc
            return

        # Full build path
        self.corpus_tokens = [self._get_doc_tokens(doc) for doc in self.documents]
        safe_corpus = [tokens if len(tokens) > 0 else ["__empty__"] for tokens in self.corpus_tokens]
        self.bm25 = BM25Okapi(safe_corpus)

        # If this build contains only clean documents, cache as base
        if not poison_docs:
            self._base_doc_ids = [d.id for d in clean_docs]
            self._base_corpus_tokens = list(self.corpus_tokens)
            self._base_bm25 = self.bm25
            self._base_doc_freqs = list(self.bm25.doc_freqs)
            self._base_doc_len = list(self.bm25.doc_len)
            self._base_num_doc = sum(self._base_doc_len)
            self._base_corpus_size = len(clean_docs)
            base_nd = {}
            for df in self._base_doc_freqs:
                for w in df:
                    base_nd[w] = base_nd.get(w, 0) + 1
            self._base_nd = base_nd
        else:
            self._base_doc_ids = None
            self._base_corpus_tokens = None
            self._base_bm25 = None
            self._base_doc_freqs = None
            self._base_doc_len = None
            self._base_num_doc = 0
            self._base_corpus_size = 0
            self._base_nd = None

    def retrieve(self, query: str, top_k: int = 5) -> List[RetrievalResult]:
        if not self.documents:
            return []

        if self.bm25 is None:
            results = []
            for rank, doc in enumerate(self.documents[:top_k], 1):
                results.append(RetrievalResult(
                    doc_id=doc.id,
                    score=0.0,
                    rank=rank,
                    title=doc.title,
                    text=doc.text,
                    is_poisoned=doc.is_poisoned,
                    doc_type=doc.doc_type,
                    poison_target_query=doc.poison_target_query,
                    poison_type=doc.poison_type,
                    metadata={"engine": self.name}
                ))
            return results

        query_tokens = self._tokenize(query)
        scores = self.bm25.get_scores(query_tokens)
        top_indices = sorted(range(len(scores)), key=lambda idx: (-scores[idx], idx))[:top_k]

        results = []
        for rank, idx in enumerate(top_indices, 1):
            doc = self.documents[idx]
            results.append(RetrievalResult(
                doc_id=doc.id,
                score=float(scores[idx]),
                rank=rank,
                title=doc.title,
                text=doc.text,
                is_poisoned=doc.is_poisoned,
                doc_type=doc.doc_type,
                poison_target_query=doc.poison_target_query,
                poison_type=doc.poison_type,
                metadata={"engine": self.name}
            ))
        return results

class DenseFAISSRetriever(BaseRetriever):
    """Dense vector retrieval engine using SentenceTransformers and FAISS.

    Embeddings are cached in RAM and persisted to disk, so repeated runs over the same
    corpus skip encoding entirely. The cache is namespaced by model, because two models
    produce incomparable vectors of the same width.
    """

    #: Files written under EMBED_CACHE_DIR/<model_slug>/.
    CACHE_KEYS_FILE = "keys.json"
    CACHE_VECTORS_FILE = "vectors.npy"
    #: New vectors to accumulate before rewriting the on-disk matrix.
    CACHE_FLUSH_THRESHOLD = 1000

    def __init__(
        self,
        model_name: str = config.DENSE_MODEL_NAME,
        query_prefix: Optional[str] = None,
        cache_dir: Optional[Path] = None,
        persist_cache: bool = True
    ):
        super().__init__("Dense-FAISS")
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)
        self.index = None
        self.embeddings = None
        # Instruction-tuned models (BGE et al.) want a prefix on the query side only.
        self.query_prefix = config.DENSE_QUERY_PREFIX if query_prefix is None else query_prefix
        self.persist_cache = persist_cache
        self.cache_dir = Path(cache_dir) if cache_dir else (config.EMBED_CACHE_DIR / self.model_slug())
        self._embedding_cache: Dict[str, np.ndarray] = {}
        self._cache_dirty = False
        self._unsaved_keys = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.encoded_count = 0
        self._base_doc_keys: Optional[List[str]] = None
        self._base_embeddings: Optional[np.ndarray] = None
        if self.persist_cache:
            self._load_disk_cache()
            # Runs that encode fewer than CACHE_FLUSH_THRESHOLD new documents would
            # otherwise never reach a flush, and every call site would have to remember to
            # call flush_cache(). Registering it here means no script can forget.
            atexit.register(self._save_disk_cache)

    def model_slug(self) -> str:
        """Filesystem-safe model identifier. Must be part of the cache path: without it a
        model swap would silently return vectors produced by the previous model."""
        return self.model_name.replace("/", "__").replace(" ", "_")

    @staticmethod
    def _cache_key(doc: CTIDocument) -> str:
        """Hash of the exact text that gets encoded.

        Hashing rather than using the document text itself keeps ~12MB of key strings from
        being rebuilt on every build_index.
        """
        payload = f"{doc.id}::{doc.title}::{doc.text}".encode("utf-8")
        return hashlib.sha1(payload).hexdigest()

    def _load_disk_cache(self):
        keys_path = self.cache_dir / self.CACHE_KEYS_FILE
        vecs_path = self.cache_dir / self.CACHE_VECTORS_FILE
        if not (keys_path.exists() and vecs_path.exists()):
            return
        try:
            keys = json.loads(keys_path.read_text(encoding="utf-8"))
            vectors = np.load(vecs_path)
            if len(keys) != vectors.shape[0]:
                raise ValueError(f"cache mismatch: {len(keys)} keys vs {vectors.shape[0]} vectors")
            self._embedding_cache = {k: vectors[i] for i, k in enumerate(keys)}
        except Exception as e:
            # A corrupt cache must never be fatal -- just re-encode.
            logger.warning(f"Ignoring unreadable embedding cache at {self.cache_dir}: {e}")
            self._embedding_cache = {}

    def _save_disk_cache(self):
        if not (self.persist_cache and self._cache_dirty and self._embedding_cache):
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        keys = list(self._embedding_cache.keys())
        vectors = np.stack([self._embedding_cache[k] for k in keys]).astype(np.float32)
        np.save(self.cache_dir / self.CACHE_VECTORS_FILE, vectors)
        (self.cache_dir / self.CACHE_KEYS_FILE).write_text(
            json.dumps(keys), encoding="utf-8"
        )
        self._cache_dirty = False
        self._unsaved_keys = 0

    def flush_cache(self):
        """Write any vectors still held only in memory. Call once a run is done indexing."""
        self._save_disk_cache()

    def build_index(self, documents: List[CTIDocument]):
        self.documents = list(documents)

        # Counters describe this index build only. They are the signal for "did the cache
        # work", so accumulating them across a run's ten build_index calls would make that
        # question unanswerable.
        self.cache_hits = 0
        self.cache_misses = 0

        # Identify documents needing encoding. Both counters are per unique key: a corpus
        # containing the same document twice is one encode, not two.
        doc_keys = [self._cache_key(doc) for doc in self.documents]
        missing_keys = []
        missing_texts = []
        seen_missing = set()
        for doc, key in zip(self.documents, doc_keys):
            if key in self._embedding_cache:
                self.cache_hits += 1
            elif key not in seen_missing:
                self.cache_misses += 1
                seen_missing.add(key)
                missing_keys.append(key)
                missing_texts.append(f"{doc.title}: {doc.text}")

        # `encoded_count` is the unambiguous check: it must be 0 on a second run over the
        # same corpus with the same model.
        self.encoded_count = len(missing_texts)

        # Batch encode missing documents
        if missing_texts:
            raw_new = self.model.encode(missing_texts, batch_size=256, convert_to_numpy=True, show_progress_bar=False)
            norm_new = raw_new / np.linalg.norm(raw_new, axis=1, keepdims=True)
            for key, emb in zip(missing_keys, norm_new):
                self._embedding_cache[key] = emb
            self._unsaved_keys += len(missing_keys)
            self._cache_dirty = True
            # Rewriting a 37MB matrix after every scenario would cost more than the encoding
            # it saves, so only flush once enough new vectors have accumulated. flush_cache()
            # covers the remainder at the end of a run.
            if self._unsaved_keys >= self.CACHE_FLUSH_THRESHOLD:
                self._save_disk_cache()

        # Assemble full embedding matrix from cache
        if (self._base_embeddings is not None
            and self._base_doc_keys is not None
            and len(doc_keys) >= len(self._base_doc_keys)
            and doc_keys[:len(self._base_doc_keys)] == self._base_doc_keys):
            poison_keys = doc_keys[len(self._base_doc_keys):]
            if poison_keys:
                poison_embs = np.array([self._embedding_cache[k] for k in poison_keys], dtype=np.float32)
                self.embeddings = np.vstack([self._base_embeddings, poison_embs])
            else:
                self.embeddings = self._base_embeddings
        else:
            all_embs = [self._embedding_cache[key] for key in doc_keys]
            self.embeddings = np.array(all_embs, dtype=np.float32)
            if not any(d.is_poisoned for d in self.documents):
                self._base_doc_keys = list(doc_keys)
                self._base_embeddings = self.embeddings

        dim = self.embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dim)
        self.index.add(self.embeddings)

    def encode_query(self, query: str) -> np.ndarray:
        """Encode a query, applying the model's query-side instruction prefix if any."""
        q_emb = self.model.encode(
            [f"{self.query_prefix}{query}"], convert_to_numpy=True, show_progress_bar=False
        )
        return q_emb / np.linalg.norm(q_emb, axis=1, keepdims=True)

    def retrieve(self, query: str, top_k: int = 5) -> List[RetrievalResult]:
        q_emb = self.encode_query(query)
        scores, indices = self.index.search(q_emb.astype(np.float32), top_k)

        results = []
        for rank, (score, idx) in enumerate(zip(scores[0], indices[0]), 1):
            if idx < 0 or idx >= len(self.documents):
                continue
            doc = self.documents[idx]
            results.append(RetrievalResult(
                doc_id=doc.id,
                score=float(score),
                rank=rank,
                title=doc.title,
                text=doc.text,
                is_poisoned=doc.is_poisoned,
                doc_type=doc.doc_type,
                poison_target_query=doc.poison_target_query,
                poison_type=doc.poison_type,
                metadata={"engine": self.name}
            ))
        return results

class HybridRerankRetriever(BaseRetriever):
    """Hybrid engine combining BM25 + Dense FAISS with Cross-Encoder Reranking."""
    def __init__(self, bm25_engine: BM25Retriever, dense_engine: DenseFAISSRetriever, reranker_name: str = config.RERANKER_MODEL_NAME):
        super().__init__("Hybrid-Reranker")
        self.bm25_engine = bm25_engine
        self.dense_engine = dense_engine
        self.reranker = CrossEncoder(reranker_name)
        # The cross-encoder is the one repeated per-query cost in a run (candidate_k pairs
        # per query, per scenario), so it is worth being able to report the actual volume.
        self.reranked_pairs = 0

    def build_index(self, documents: List[CTIDocument]):
        self.documents = list(documents)
        self.bm25_engine.build_index(documents)
        self.dense_engine.build_index(documents)

    def retrieve(self, query: str, top_k: int = 5, candidate_k: int = 10) -> List[RetrievalResult]:
        # 1. Retrieve candidate pools from both BM25 and Dense
        bm25_res = self.bm25_engine.retrieve(query, top_k=candidate_k)
        dense_res = self.dense_engine.retrieve(query, top_k=candidate_k)

        # 2. Reciprocal Rank Fusion (RRF) candidate pooling
        rrf_scores: Dict[str, float] = {}
        doc_map: Dict[str, CTIDocument] = {d.id: d for d in self.documents}

        for rank, r in enumerate(bm25_res, 1):
            rrf_scores[r.doc_id] = rrf_scores.get(r.doc_id, 0.0) + (1.0 / (config.RRF_K + rank))
        for rank, r in enumerate(dense_res, 1):
            rrf_scores[r.doc_id] = rrf_scores.get(r.doc_id, 0.0) + (1.0 / (config.RRF_K + rank))

        # Sort candidate doc IDs by RRF
        sorted_candidates = sorted(rrf_scores.keys(), key=lambda k: rrf_scores[k], reverse=True)[:candidate_k]

        # 3. Cross-Encoder Reranking.
        # `query` is the raw user query: the dense engine applies its instruction prefix
        # internally, in encode_query(). Feeding a BGE prefix to an ms-marco cross-encoder
        # would be a silent quality regression across every reranked pair in a run.
        pairs = [[query, f"{doc_map[did].title}: {doc_map[did].text}"] for did in sorted_candidates]
        cross_scores = self.reranker.predict(pairs, batch_size=config.RERANKER_BATCH_SIZE)
        self.reranked_pairs += len(pairs)

        rerank_indices = np.argsort(cross_scores)[::-1][:top_k]
        results = []
        for rank, idx in enumerate(rerank_indices, 1):
            doc_id = sorted_candidates[idx]
            doc = doc_map[doc_id]
            results.append(RetrievalResult(
                doc_id=doc.id,
                score=float(cross_scores[idx]),
                rank=rank,
                title=doc.title,
                text=doc.text,
                is_poisoned=doc.is_poisoned,
                doc_type=doc.doc_type,
                poison_target_query=doc.poison_target_query,
                poison_type=doc.poison_type,
                metadata={"engine": self.name, "raw_cross_score": float(cross_scores[idx])}
            ))
        return results

class GraphRAGRetriever(BaseRetriever):
    """Knowledge Graph retrieval engine based on Entity-Relation Subgraph Traversal."""
    STOPWORDS = CTI_STOPWORDS

    def __init__(self):
        super().__init__("GraphRAG")
        self.graph = nx.MultiDiGraph()
        self.doc_map: Dict[str, CTIDocument] = {}
        self._base_graph: Optional[nx.MultiDiGraph] = None
        self._base_doc_map: Optional[Dict[str, CTIDocument]] = None
        self._base_entities: Optional[set] = None
        self._base_doc_ids: Optional[set] = None

        # Tracking for newly added poison elements to support zero-copy incremental rollback
        self._added_nodes: List[str] = []
        self._added_edges: List[Tuple[Any, Any, int]] = []
        self._added_doc_ids: List[str] = []

        # Fast inverted entity lookup structures
        self._entity_candidates: List[Tuple[str, str, re.Pattern, int]] = []
        self._entity_inverted_index: Dict[str, List[int]] = {}
        self._delta_entity_candidates: List[Tuple[str, str, re.Pattern, int]] = []
        self._delta_inverted_index: Dict[str, List[int]] = {}
        self._tracked_node_count: int = 0
        self._tracked_edge_count: int = 0

    def rollback_poison(self):
        """Rolls back newly added poison nodes, edges, and documents to restore base clean graph."""
        if not (self._added_nodes or self._added_edges or self._added_doc_ids):
            if self._base_doc_map is not None:
                self.doc_map = dict(self._base_doc_map)
            return
        for u, v, key in reversed(self._added_edges):
            if self.graph.has_edge(u, v, key=key):
                self.graph.remove_edge(u, v, key=key)
        for n in reversed(self._added_nodes):
            if self.graph.has_node(n):
                self.graph.remove_node(n)
        if self._base_doc_map is not None:
            self.doc_map = dict(self._base_doc_map)
        else:
            for doc_id in self._added_doc_ids:
                self.doc_map.pop(doc_id, None)

        self._added_nodes.clear()
        self._added_edges.clear()
        self._added_doc_ids.clear()
        self._delta_entity_candidates.clear()
        self._delta_inverted_index.clear()
        self._tracked_node_count = self.graph.number_of_nodes()
        self._tracked_edge_count = self.graph.number_of_edges()

    def _build_base_entity_index(self):
        self._entity_candidates.clear()
        self._entity_inverted_index.clear()
        self._delta_entity_candidates.clear()
        self._delta_inverted_index.clear()
        for node, data in self.graph.nodes(data=True):
            if data.get("node_type") != "entity":
                continue
            raw_node = str(node)[4:] if str(node).startswith("ent:") else str(node)
            node_str = raw_node.strip()
            if len(node_str) < 2:
                continue
            if len(node_str) == 2 and not (node_str.isupper() or re.match(r"^[A-Z][0-9]$|^[A-Z]{2}$", node_str)):
                continue
            if node_str.lower() in self.STOPWORDS:
                continue
            s_lower = node_str.lower()
            escaped = re.escape(s_lower)
            prefix = r"\b" if re.match(r"^\w", node_str) else ""
            suffix = r"\b" if re.search(r"\w$", node_str) else ""
            pat = re.compile(rf"{prefix}{escaped}{suffix}")
            words = set(re.findall(r"\w+", s_lower))
            cand_id = len(self._entity_candidates)
            self._entity_candidates.append((raw_node, s_lower, pat, cand_id))
            if words:
                for w in words:
                    self._entity_inverted_index.setdefault(w, []).append(cand_id)
            else:
                self._entity_inverted_index.setdefault("__special__", []).append(cand_id)
        self._tracked_node_count = self.graph.number_of_nodes()
        self._tracked_edge_count = self.graph.number_of_edges()

    def _add_delta_entity(self, raw_entity: str):
        raw_entity_str = str(raw_entity)[4:] if str(raw_entity).startswith("ent:") else str(raw_entity)
        node_str = raw_entity_str.strip()
        if len(node_str) < 2:
            return
        if len(node_str) == 2 and not (node_str.isupper() or re.match(r"^[A-Z][0-9]$|^[A-Z]{2}$", node_str)):
            return
        if node_str.lower() in self.STOPWORDS:
            return
        s_lower = node_str.lower()
        escaped = re.escape(s_lower)
        prefix = r"\b" if re.match(r"^\w", node_str) else ""
        suffix = r"\b" if re.search(r"\w$", node_str) else ""
        pat = re.compile(rf"{prefix}{escaped}{suffix}")
        words = set(re.findall(r"\w+", s_lower))
        cand_id = len(self._delta_entity_candidates)
        self._delta_entity_candidates.append((raw_entity_str, s_lower, pat, cand_id))
        if words:
            for w in words:
                self._delta_inverted_index.setdefault(w, []).append(cand_id)
        else:
            self._delta_inverted_index.setdefault("__special__", []).append(cand_id)

    def build_index(self, documents: List[CTIDocument]):
        # Roll back any previously added poison nodes/edges
        self.rollback_poison()

        self.documents = list(documents)
        if not self.documents:
            self.graph.clear()
            self.doc_map = {}
            self._base_graph = None
            self._base_doc_map = None
            self._base_entities = None
            self._base_doc_ids = None
            self._entity_candidates.clear()
            self._entity_inverted_index.clear()
            self._delta_entity_candidates.clear()
            self._delta_inverted_index.clear()
            self._tracked_node_count = 0
            self._tracked_edge_count = 0
            return

        clean_docs = [d for d in self.documents if not d.is_poisoned]
        poison_docs = [d for d in self.documents if d.is_poisoned]

        # Fast incremental path: if base clean graph exists and clean docs match base exactly
        if (self._base_doc_ids is not None 
            and len(clean_docs) == len(self._base_doc_ids)
            and all(d.id in self._base_doc_ids for d in clean_docs)):

            if not poison_docs:
                self._tracked_node_count = self.graph.number_of_nodes()
                self._tracked_edge_count = self.graph.number_of_edges()
                return

            all_declared_entities = self._base_entities.union({e for d in poison_docs for e in d.entities})
            for doc in poison_docs:
                doc_node = f"doc:{doc.id}"
                self.doc_map[doc.id] = doc
                self._added_doc_ids.append(doc.id)
                self.graph.add_node(doc_node, node_type="document", title=doc.title, is_poisoned=doc.is_poisoned)
                self._added_nodes.append(doc_node)

                for entity in doc.entities:
                    ent_node = f"ent:{entity}"
                    if not self.graph.has_node(ent_node):
                        self.graph.add_node(ent_node, node_type="entity")
                        self._added_nodes.append(ent_node)
                        self._add_delta_entity(entity)
                    k1 = self.graph.add_edge(doc_node, ent_node, relation="MENTIONS")
                    self._added_edges.append((doc_node, ent_node, k1))
                    k2 = self.graph.add_edge(ent_node, doc_node, relation="MENTIONED_IN")
                    self._added_edges.append((ent_node, doc_node, k2))

                for rel in doc.relations:
                    src, rel_type, tgt = rel["source"], rel["relation"], rel["target"]
                    src_is_ent = (src in all_declared_entities) or (src not in self.doc_map)
                    tgt_is_ent = (tgt in all_declared_entities) or (tgt not in self.doc_map)

                    src_node = f"ent:{src}" if src_is_ent else f"doc:{src}"
                    tgt_node = f"ent:{tgt}" if tgt_is_ent else f"doc:{tgt}"

                    if src_is_ent and not self.graph.has_node(src_node):
                        self.graph.add_node(src_node, node_type="entity")
                        self._added_nodes.append(src_node)
                        self._add_delta_entity(src)
                    if tgt_is_ent and not self.graph.has_node(tgt_node):
                        self.graph.add_node(tgt_node, node_type="entity")
                        self._added_nodes.append(tgt_node)
                        self._add_delta_entity(tgt)

                    k = self.graph.add_edge(src_node, tgt_node, relation=rel_type)
                    self._added_edges.append((src_node, tgt_node, k))

                    # Cross-link if one is entity and one is doc
                    if not src_is_ent and tgt_is_ent:
                        k = self.graph.add_edge(tgt_node, src_node, relation="MENTIONED_IN")
                        self._added_edges.append((tgt_node, src_node, k))
                    elif src_is_ent and not tgt_is_ent:
                        k = self.graph.add_edge(tgt_node, src_node, relation="MENTIONS")
                        self._added_edges.append((tgt_node, src_node, k))
            self._tracked_node_count = self.graph.number_of_nodes()
            self._tracked_edge_count = self.graph.number_of_edges()
            return

        # Full build path
        self.graph.clear()
        self.doc_map = {doc.id: doc for doc in self.documents}
        all_declared_entities = {e for d in self.documents for e in d.entities}

        for doc in self.documents:
            doc_node = f"doc:{doc.id}"
            self.graph.add_node(doc_node, node_type="document", title=doc.title, is_poisoned=doc.is_poisoned)
            for entity in doc.entities:
                ent_node = f"ent:{entity}"
                if not self.graph.has_node(ent_node):
                    self.graph.add_node(ent_node, node_type="entity")
                self.graph.add_edge(doc_node, ent_node, relation="MENTIONS")
                self.graph.add_edge(ent_node, doc_node, relation="MENTIONED_IN")

            for rel in doc.relations:
                src, rel_type, tgt = rel["source"], rel["relation"], rel["target"]
                src_is_ent = (src in all_declared_entities) or (src not in self.doc_map)
                tgt_is_ent = (tgt in all_declared_entities) or (tgt not in self.doc_map)

                src_node = f"ent:{src}" if src_is_ent else f"doc:{src}"
                tgt_node = f"ent:{tgt}" if tgt_is_ent else f"doc:{tgt}"

                if src_is_ent and not self.graph.has_node(src_node):
                    self.graph.add_node(src_node, node_type="entity")
                if tgt_is_ent and not self.graph.has_node(tgt_node):
                    self.graph.add_node(tgt_node, node_type="entity")

                self.graph.add_edge(src_node, tgt_node, relation=rel_type)

                # Cross-link if one is entity and one is doc
                if not src_is_ent and tgt_is_ent:
                    self.graph.add_edge(tgt_node, src_node, relation="MENTIONED_IN")
                elif src_is_ent and not tgt_is_ent:
                    self.graph.add_edge(tgt_node, src_node, relation="MENTIONS")

        if not poison_docs:
            self._base_graph = self.graph.copy()
            self._base_doc_map = dict(self.doc_map)
            self._base_entities = set(all_declared_entities)
            self._base_doc_ids = {d.id for d in clean_docs}
            self._build_base_entity_index()
        else:
            self._base_graph = None
            self._base_doc_map = None
            self._base_entities = None
            self._base_doc_ids = None
            self._build_base_entity_index()

        self._tracked_node_count = self.graph.number_of_nodes()
        self._tracked_edge_count = self.graph.number_of_edges()

    def _extract_query_entities(self, query: str) -> List[str]:
        """Matches query against graph entities using fast inverted index and word boundary regex."""
        q_lower = query.lower()
        if not q_lower.strip():
            return []

        tokens = re.findall(r'[a-zA-Z0-9_\-\.]+', q_lower)
        if not tokens or all(t in self.STOPWORDS for t in tokens):
            return []

        # If external modifications changed graph node/edge count directly outside build_index, reindex
        if (self._tracked_node_count != self.graph.number_of_nodes()
            or self._tracked_edge_count != self.graph.number_of_edges()):
            self._build_base_entity_index()

        q_words = set(re.findall(r"\w+", q_lower))
        cand_ids = set()
        for w in q_words:
            if w in self._entity_inverted_index:
                cand_ids.update(self._entity_inverted_index[w])
        if "__special__" in self._entity_inverted_index:
            cand_ids.update(self._entity_inverted_index["__special__"])

        delta_cand_ids = set()
        if self._delta_inverted_index:
            for w in q_words:
                if w in self._delta_inverted_index:
                    delta_cand_ids.update(self._delta_inverted_index[w])
            if "__special__" in self._delta_inverted_index:
                delta_cand_ids.update(self._delta_inverted_index["__special__"])

        matched = []
        for c_id in sorted(cand_ids):
            raw_node, s_lower, pat, _ = self._entity_candidates[c_id]
            if s_lower in q_lower and pat.search(q_lower):
                matched.append(raw_node)
        for c_id in sorted(delta_cand_ids):
            raw_node, s_lower, pat, _ = self._delta_entity_candidates[c_id]
            if s_lower in q_lower and pat.search(q_lower):
                matched.append(raw_node)
        return matched

    def retrieve(self, query: str, top_k: int = 5) -> List[RetrievalResult]:
        if not self.documents:
            return []

        matched_entities = self._extract_query_entities(query)
        doc_scores: Dict[str, float] = {}
        fallback_used = False

        # 1-hop and 2-hop degree-normalized neighborhood expansion with decay
        for entity in matched_entities:
            ent_node = entity if self.graph.has_node(entity) else f"ent:{entity}"
            if not self.graph.has_node(ent_node):
                continue
            deg_entity = max(1, self.graph.degree(ent_node))
            # Normalization based on query entity degree with mild square-root scaling:
            # penalizes hub inflation without penalizing rich CTI documents.
            norm_w1 = 2.0 / math.sqrt(deg_entity)
            one_hop_docs = set()

            # 1-hop: entity -> neighbor (doc)
            for neighbor in self.graph.neighbors(ent_node):
                if str(neighbor).startswith("doc:"):
                    doc_id = str(neighbor)[4:]
                    if doc_id in self.doc_map:
                        one_hop_docs.add(doc_id)
                        doc_scores[doc_id] = doc_scores.get(doc_id, 0.0) + norm_w1

            # 2-hop: entity -> neighbor (entity) -> second_hop (doc)
            for neighbor in self.graph.neighbors(ent_node):
                if not str(neighbor).startswith("doc:"):
                    deg_neighbor = max(1, self.graph.degree(neighbor))
                    for second_hop in self.graph.neighbors(neighbor):
                        if str(second_hop).startswith("doc:"):
                            second_doc_id = str(second_hop)[4:]
                            if second_doc_id in self.doc_map and second_doc_id not in one_hop_docs:
                                # Attenuated 2-hop diffusion bounded by query entity degree transition
                                norm_w2 = 0.5 / (deg_neighbor * deg_entity)
                                doc_scores[second_doc_id] = doc_scores.get(second_doc_id, 0.0) + norm_w2

        if not doc_scores:
            fallback_used = True
            logger.warning(f"Graph traversal yielded no results for query: {query}. Falling back to lexical search.")
            # Fallback to lexical token match
            for doc in self.documents:
                match_count = sum(1 for w in query.lower().split() if w in doc.text.lower())
                if match_count > 0:
                    doc_scores[doc.id] = float(match_count)

            if not doc_scores and self.documents:
                for doc in self.documents[:top_k]:
                    doc_scores[doc.id] = 0.0

        # Stable tie-breaking: sort by (-score, doc_id)
        sorted_docs = sorted(doc_scores.keys(), key=lambda k: (-doc_scores[k], k))[:top_k]

        results = []
        for rank, doc_id in enumerate(sorted_docs, 1):
            doc = self.doc_map.get(doc_id)
            if doc:
                results.append(RetrievalResult(
                    doc_id=doc.id,
                    score=float(doc_scores[doc_id]),
                    rank=rank,
                    title=doc.title,
                    text=doc.text,
                    is_poisoned=doc.is_poisoned,
                    doc_type=doc.doc_type,
                    poison_target_query=doc.poison_target_query,
                    poison_type=doc.poison_type,
                    metadata={
                        "engine": self.name,
                        "matched_entities": matched_entities,
                        "fallback_used": fallback_used
                    }
                ))
        return results
