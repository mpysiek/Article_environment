import re
import numpy as np
import networkx as nx
from typing import List, Dict, Any, Optional
from rank_bm25 import BM25Okapi
import faiss
from sentence_transformers import SentenceTransformer, CrossEncoder

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

class BM25Retriever(BaseRetriever):
    """Sparse lexical retrieval engine based on BM25 Okapi."""
    def __init__(self):
        super().__init__("Sparse-BM25")
        self.bm25 = None
        self.corpus_tokens = []

    def _tokenize(self, text: str) -> List[str]:
        text = text.lower()
        tokens = re.findall(r'[a-zA-Z0-9_\-\.]+', text)
        return tokens

    def build_index(self, documents: List[CTIDocument]):
        self.documents = list(documents)
        self.corpus_tokens = [self._tokenize(doc.title + " " + doc.text) for doc in self.documents]
        self.bm25 = BM25Okapi(self.corpus_tokens)

    def retrieve(self, query: str, top_k: int = 5) -> List[RetrievalResult]:
        query_tokens = self._tokenize(query)
        scores = self.bm25.get_scores(query_tokens)
        top_indices = np.argsort(scores)[::-1][:top_k]

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
                metadata={"engine": self.name}
            ))
        return results

class DenseFAISSRetriever(BaseRetriever):
    """Dense vector retrieval engine using SentenceTransformers and FAISS with embedding caching."""
    def __init__(self, model_name: str = config.DENSE_MODEL_NAME):
        super().__init__("Dense-FAISS")
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)
        self.index = None
        self.embeddings = None
        self._embedding_cache: Dict[str, np.ndarray] = {}

    def build_index(self, documents: List[CTIDocument]):
        self.documents = list(documents)
        
        # Identify documents needing encoding
        missing_indices = []
        missing_texts = []
        for idx, doc in enumerate(self.documents):
            cache_key = f"{doc.id}::{doc.title}::{doc.text}"
            if cache_key not in self._embedding_cache:
                missing_indices.append((idx, cache_key))
                missing_texts.append(f"{doc.title}: {doc.text}")

        # Batch encode missing documents
        if missing_texts:
            raw_new = self.model.encode(missing_texts, batch_size=256, convert_to_numpy=True, show_progress_bar=False)
            norm_new = raw_new / np.linalg.norm(raw_new, axis=1, keepdims=True)
            for (idx, key), emb in zip(missing_indices, norm_new):
                self._embedding_cache[key] = emb

        # Assemble full embedding matrix from cache
        all_embs = [self._embedding_cache[f"{doc.id}::{doc.title}::{doc.text}"] for doc in self.documents]
        self.embeddings = np.array(all_embs, dtype=np.float32)
        dim = self.embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dim)
        self.index.add(self.embeddings)

    def retrieve(self, query: str, top_k: int = 5) -> List[RetrievalResult]:
        q_emb = self.model.encode([query], convert_to_numpy=True, show_progress_bar=False)
        q_emb = q_emb / np.linalg.norm(q_emb, axis=1, keepdims=True)
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

        # 3. Cross-Encoder Reranking
        pairs = [[query, f"{doc_map[did].title}: {doc_map[did].text}"] for did in sorted_candidates]
        cross_scores = self.reranker.predict(pairs)

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
                metadata={"engine": self.name, "raw_cross_score": float(cross_scores[idx])}
            ))
        return results

class GraphRAGRetriever(BaseRetriever):
    """Knowledge Graph retrieval engine based on Entity-Relation Subgraph Traversal."""
    def __init__(self):
        super().__init__("GraphRAG")
        self.graph = nx.MultiDiGraph()
        self.doc_map: Dict[str, CTIDocument] = {}

    def build_index(self, documents: List[CTIDocument]):
        self.documents = list(documents)
        self.graph.clear()
        self.doc_map = {doc.id: doc for doc in self.documents}

        # Build Knowledge Graph: Document nodes, Entity nodes, and Relations
        for doc in self.documents:
            self.graph.add_node(doc.id, node_type="document", title=doc.title, is_poisoned=doc.is_poisoned)
            for entity in doc.entities:
                self.graph.add_node(entity, node_type="entity")
                self.graph.add_edge(doc.id, entity, relation="MENTIONS")
                self.graph.add_edge(entity, doc.id, relation="MENTIONED_IN")

            for rel in doc.relations:
                src, rel_type, tgt = rel["source"], rel["relation"], rel["target"]
                self.graph.add_node(src, node_type="entity")
                self.graph.add_node(tgt, node_type="entity")
                self.graph.add_edge(src, tgt, relation=rel_type)

    def _extract_query_entities(self, query: str) -> List[str]:
        """Matches query against graph entities."""
        matched = []
        q_lower = query.lower()
        for node, data in self.graph.nodes(data=True):
            if str(node).lower() in q_lower:
                matched.append(str(node))
        return matched

    def retrieve(self, query: str, top_k: int = 5) -> List[RetrievalResult]:
        matched_entities = self._extract_query_entities(query)
        doc_scores: Dict[str, float] = {}

        # 1-hop and 2-hop neighborhood expansion with decay
        for entity in matched_entities:
            # 1-hop
            for neighbor in self.graph.neighbors(entity):
                if neighbor in self.doc_map:
                    doc_scores[neighbor] = doc_scores.get(neighbor, 0.0) + 2.0
                # 2-hop
                for second_hop in self.graph.neighbors(neighbor):
                    if second_hop in self.doc_map:
                        doc_scores[second_hop] = doc_scores.get(second_hop, 0.0) + 1.0

        if not doc_scores:
            # Fallback to lexical token match
            for doc in self.documents:
                match_count = sum(1 for w in query.lower().split() if w in doc.text.lower())
                if match_count > 0:
                    doc_scores[doc.id] = float(match_count)

        sorted_docs = sorted(doc_scores.keys(), key=lambda k: doc_scores[k], reverse=True)[:top_k]

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
                    metadata={"engine": self.name, "matched_entities": matched_entities}
                ))
        return results
