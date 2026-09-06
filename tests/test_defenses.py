import pytest
from src.corpus.dataset import build_cti_knowledge_base, build_gold_benchmark_queries, CTIDocument
from src.defense.sanitizers import EntropyPerplexityFilter, GraphConsensusValidator, SemanticDiscrepancyFilter, DefendedRetrievalPipeline
from src.engines.retrievers import BM25Retriever, GraphRAGRetriever
from src.attacks.poisoning import SparseKeywordStuffingAttacker, GraphLogicPoisonAttacker

def test_entropy_filter_detects_keyword_stuffing():
    attacker = SparseKeywordStuffingAttacker()
    queries = build_gold_benchmark_queries()
    poison_doc = attacker.generate_poison(queries[0])

    filter_obj = EntropyPerplexityFilter()
    is_susp, reason = filter_obj.is_suspicious(poison_doc.text)
    assert is_susp is True, f"Expected suspicious detection for stuffed doc: {reason}"

def test_entropy_filter_passes_clean_doc():
    clean_docs = build_cti_knowledge_base()
    filter_obj = EntropyPerplexityFilter()
    for doc in clean_docs:
        is_susp, reason = filter_obj.is_suspicious(doc.text)
        assert is_susp is False, f"Clean doc {doc.id} falsely flagged: {reason}"

def test_graph_validator_blocks_ontology_violation():
    validator = GraphConsensusValidator()
    is_valid, reason = validator.is_relation_valid("CVE-2021-44228", "CLASSIFIED_AS", "BENIGN_SAFE_ENTITY")
    assert is_valid is False
    assert "Ontology violation" in reason

def test_defended_bm25_blocks_poison():
    clean_docs = build_cti_knowledge_base()
    queries = build_gold_benchmark_queries()
    attacker = SparseKeywordStuffingAttacker()
    poison_doc = attacker.generate_poison(queries[0])

    bm25 = BM25Retriever()
    defended_pipeline = DefendedRetrievalPipeline(bm25)

    sanitized_corpus = defended_pipeline.filter_documents(clean_docs + [poison_doc])
    assert len(sanitized_corpus) == len(clean_docs), "Poisoned doc was not filtered during ingestion"
