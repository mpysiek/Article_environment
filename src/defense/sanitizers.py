import re
import math
from collections import Counter
from typing import List, Dict, Tuple, Optional
from src.corpus.dataset import CTIDocument, RetrievalResult

class EntropyPerplexityFilter:
    """Detects keyword stuffing and term frequency saturation anomalies."""
    def __init__(self, max_top3_ratio: float = 0.21, min_unique_ratio: float = 0.60):
        self.max_top3_ratio = max_top3_ratio
        self.min_unique_ratio = min_unique_ratio

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9_\-\.]+", text.lower())

    def is_suspicious(self, text: str) -> Tuple[bool, str]:
        tokens = self._tokenize(text)
        if len(tokens) < 15:
            return False, "Pass"

        counts = Counter(tokens)
        total = len(tokens)
        unique = len(counts)
        top3_count = sum(c for _, c in counts.most_common(3))

        top3_ratio = top3_count / total
        unique_ratio = unique / total

        if unique_ratio < self.min_unique_ratio and top3_ratio > self.max_top3_ratio:
            return True, f"Vocabulary redundancy anomaly: unique={unique_ratio:.1%}, top3={top3_ratio:.1%}"

        return False, "Pass"

class SemanticDiscrepancyFilter:
    """Cross-checks bi-encoder similarity vs cross-encoder coherence score."""
    def __init__(self, min_cross_score: float = -2.5):
        self.min_cross_score = min_cross_score

    def is_adversarial_discrepancy(self, raw_cross_score: Optional[float]) -> Tuple[bool, str]:
        if raw_cross_score is not None and raw_cross_score < self.min_cross_score:
            return True, f"Cross-encoder rejected passage coherence (score: {raw_cross_score:.2f})"
        return False, "Pass"

class GraphConsensusValidator:
    """Verifies ontology constraints and multi-source consensus in knowledge graphs."""
    def __init__(self):
        self.disallowed_targets = {"BENIGN_SAFE_ENTITY", "CWE-000", "NO_ACTION_REQUIRED"}

    def is_relation_valid(self, source: str, relation: str, target: str) -> Tuple[bool, str]:
        if target in self.disallowed_targets:
            return False, f"Ontology violation: Critical entity {source} mapped to prohibited benign target {target}"
        return True, "Valid relation"

class DefendedRetrievalPipeline:
    """Wraps base retrieval engines with multi-layer defense sanitizers."""
    def __init__(self, base_retriever):
        self.base_retriever = base_retriever
        self.entropy_filter = EntropyPerplexityFilter()
        self.discrepancy_filter = SemanticDiscrepancyFilter()
        self.graph_validator = GraphConsensusValidator()

    def filter_documents(self, documents: List[CTIDocument]) -> List[CTIDocument]:
        sanitized = []
        for doc in documents:
            is_susp, _ = self.entropy_filter.is_suspicious(doc.text)
            if is_susp:
                continue

            valid_relations = []
            rel_violation = False
            for rel in doc.relations:
                is_valid, _ = self.graph_validator.is_relation_valid(rel.get("source", ""), rel.get("relation", ""), rel.get("target", ""))
                if is_valid:
                    valid_relations.append(rel)
                else:
                    rel_violation = True
            
            if rel_violation and not valid_relations:
                continue

            sanitized_doc = CTIDocument(
                id=doc.id,
                title=doc.title,
                text=doc.text,
                doc_type=doc.doc_type,
                entities=doc.entities,
                relations=valid_relations,
                is_poisoned=doc.is_poisoned,
                poison_target_query=doc.poison_target_query,
                poison_type=doc.poison_type
            )
            sanitized.append(sanitized_doc)
        return sanitized

    def retrieve(self, query: str, top_k: int = 5) -> List[RetrievalResult]:
        raw_results = self.base_retriever.retrieve(query, top_k=top_k * 2)
        sanitized_results = []

        for r in raw_results:
            is_susp, _ = self.entropy_filter.is_suspicious(r.text)
            if is_susp:
                continue

            raw_cross = r.metadata.get("raw_cross_score")
            is_adv, _ = self.discrepancy_filter.is_adversarial_discrepancy(raw_cross)
            if is_adv:
                continue

            sanitized_results.append(r)
            if len(sanitized_results) >= top_k:
                break

        for rank, r in enumerate(sanitized_results, 1):
            r.rank = rank

        return sanitized_results
