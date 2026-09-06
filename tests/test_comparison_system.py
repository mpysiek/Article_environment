import pytest
from src.corpus.dataset import build_cti_knowledge_base, build_gold_benchmark_queries, CTIDocument, GoldQuery, RetrievalResult
from src.engines.retrievers import BM25Retriever, DenseFAISSRetriever, HybridRerankRetriever, GraphRAGRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.evaluation.llm_judge import JudgeVerdict, LLMJudge
from src.evaluation.metrics import Evaluator
from src.llm.rag_generator import RAGGenerator

def test_engines_indexing_and_retrieval():
    clean_docs = build_cti_knowledge_base()
    queries = build_gold_benchmark_queries()
    
    bm25 = BM25Retriever()
    dense = DenseFAISSRetriever()
    hybrid = HybridRerankRetriever(bm25, dense)
    graph = GraphRAGRetriever()

    for engine in [bm25, dense, hybrid, graph]:
        engine.build_index(clean_docs)
        results = engine.retrieve(queries[0].query_text, top_k=3)
        assert len(results) > 0
        assert isinstance(results[0], RetrievalResult)
        assert results[0].doc_id != ""

def test_poison_generator_injects_all_attack_types():
    clean_docs = build_cti_knowledge_base()
    queries = build_gold_benchmark_queries()
    poison_mgr = CorpusPoisonManager()

    for attack_type in ["sparse", "dense", "hybrid", "graph"]:
        poisoned_corpus = poison_mgr.generate_poisoned_corpus(clean_docs, queries, attack_type)
        assert len(poisoned_corpus) == len(clean_docs) + len(queries)
        poisoned_docs = [d for d in poisoned_corpus if d.is_poisoned]
        assert len(poisoned_docs) == len(queries)
        assert poisoned_docs[0].poison_type is not None

def test_evaluator_metrics_computation():
    queries = build_gold_benchmark_queries()
    dummy_outputs = {
        queries[0].id: [
            RetrievalResult(
                doc_id=queries[0].ground_truth_doc_ids[0],
                score=1.0,
                rank=1,
                title="Test",
                text="Clean text",
                is_poisoned=False,
                doc_type="cve"
            )
        ]
    }
    dummy_gen = {queries[0].id: "Clean factual answer"}
    dummy_judge = {queries[0].id: JudgeVerdict(is_poison_adopted=False, is_ground_truth_retained=True, detected_conflict=False, reasoning="Pass")}

    res = Evaluator.evaluate_engine_with_llm(
        engine_name="TestEngine",
        attack_type="clean",
        queries=[queries[0]],
        retrieval_outputs=dummy_outputs,
        generated_responses=dummy_gen,
        judge_verdicts=dummy_judge
    )
    assert res.generation_asr == 0.0
    assert res.ground_truth_retention == 1.0
    assert res.retrieval_asr_top1 == 0.0

def test_rag_generator_prompt_formatting():
    generator = RAGGenerator()
    dummy_results = [
        RetrievalResult(
            doc_id="CVE-2021-44228",
            score=0.9,
            rank=1,
            title="Log4j2 RCE",
            text="Apache Log4j2 JNDI vulnerability.",
            is_poisoned=False,
            doc_type="cve"
        )
    ]
    context = generator.format_context(dummy_results)
    assert "CVE-2021-44228" in context
    assert "Log4j2 RCE" in context
