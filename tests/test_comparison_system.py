import pytest
from src.corpus.dataset import build_cti_knowledge_base, build_gold_benchmark_queries, CTIDocument, GoldQuery, RetrievalResult
from src.engines.retrievers import BM25Retriever, DenseFAISSRetriever, HybridRerankRetriever, GraphRAGRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.evaluation.metrics import Evaluator

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
    res = Evaluator.evaluate_engine(
        engine_name="TestEngine",
        attack_type="clean",
        queries=[queries[0]],
        retrieval_outputs=dummy_outputs,
    )
    assert res.retrieval_asr_top1 == 0.0
    assert res.clean_recall_top5 == 1.0 / len(queries[0].ground_truth_doc_ids)
    assert res.clean_mrr == 1.0
    # The generation stage was removed; its stored-format fields stay constant.
    assert res.llm_stage_ran is False
    assert res.generation_asr == 0.0

def test_graphrag_entity_extraction_word_boundaries_and_stopwords():
    graph = GraphRAGRetriever()
    doc = CTIDocument(
        id="DOC-1",
        title="Threat Advisory",
        text="Sample text",
        doc_type="advisory",
        entities=["to", "at", "actor", "CVE-2021-44228", "Fancy Bear", "C2", "DoS", "IoC", "PoC"],
        relations=[{"source": "actor", "relation": "ATTRIBUTED_TO", "target": "DOC-1"}]
    )
    graph.build_index([doc])

    # "to" should NOT match "What threat actor uses PowerShell?" as a substring of "actor"
    matched = graph._extract_query_entities("What threat actor uses PowerShell?")
    assert "to" not in matched
    assert "at" not in matched
    assert "actor" in matched

    # Document node ID "DOC-1" must NOT be extracted as an entity even if referenced in query
    matched_doc = graph._extract_query_entities("Show me document DOC-1 details")
    assert "DOC-1" not in matched_doc

    # Valid CTI acronyms (2-char and 3-char mixed-case) must be extracted
    matched_cti = graph._extract_query_entities("Command and control C2 server vulnerability causing DoS via PoC and IoC telemetry")
    assert "C2" in matched_cti
    assert "DoS" in matched_cti
    assert "IoC" in matched_cti
    assert "PoC" in matched_cti

    # Specific CVE with boundary should match
    matched_cve = graph._extract_query_entities("Analysis of CVE-2021-44228 weakness")
    assert "CVE-2021-44228" in matched_cve

def test_graphrag_degree_normalization():
    graph = GraphRAGRetriever()
    clean_doc = CTIDocument(
        id="DOC_CLEAN",
        title="Log4j",
        text="Apache Log4j",
        doc_type="cve",
        entities=["Log4Shell"],
        relations=[]
    )
    # Poison document with 40 artificial bridges
    bridge_relations = []
    bridge_entities = []
    for i in range(40):
        b_name = f"Bridge_{i}"
        bridge_entities.append(b_name)
        bridge_relations.append({"source": "Log4Shell", "relation": "USES", "target": b_name})
        bridge_relations.append({"source": b_name, "relation": "ATTRIBUTED_TO", "target": "DOC_POISON"})
    
    poison_doc = CTIDocument(
        id="DOC_POISON",
        title="Poison Advisory",
        text="Fake notice",
        doc_type="poison",
        entities=["Log4Shell"] + bridge_entities,
        relations=bridge_relations,
        is_poisoned=True
    )
    graph.build_index([clean_doc, poison_doc])
    results = graph.retrieve("What is Log4Shell?", top_k=2)
    assert len(results) > 0
    # Clean doc should beat poison doc due to degree-normalized decay penalizing artificial bridges
    scores = {r.doc_id: r.score for r in results}
    assert "DOC_CLEAN" in scores
    assert scores["DOC_CLEAN"] > 0
    assert results[0].doc_id == "DOC_CLEAN"

def test_attackers_query_echo_ablation():
    from src.attacks.poisoning import (
        SparseKeywordStuffingAttacker,
        DenseSemanticPoisonAttacker,
        HybridEvasionAttacker,
        GraphLogicPoisonAttacker
    )
    q = GoldQuery(
        id="Q-TEST",
        query_text="Exact query text for vulnerability CVE-2024-9999",
        category="cve_lookup",
        ground_truth_doc_ids=["DOC-1"],
        ground_truth_answer="True fact",
        target_poison_assertion="Adversarial false claim",
        key_terms=["CVE-2024-9999", "vulnerability"]
    )

    attackers = [
        SparseKeywordStuffingAttacker,
        DenseSemanticPoisonAttacker,
        HybridEvasionAttacker,
        GraphLogicPoisonAttacker
    ]

    for AttackerCls in attackers:
        echo_attacker = AttackerCls(query_echo=True)
        no_echo_attacker = AttackerCls(query_echo=False)

        doc_echo = echo_attacker.generate_poison(q)
        doc_no_echo = no_echo_attacker.generate_poison(q)

        assert q.query_text in doc_echo.text, f"{AttackerCls.__name__} did not include query_text when query_echo=True"
        assert q.query_text not in doc_no_echo.text, f"{AttackerCls.__name__} leaked query_text when query_echo=False"
        assert q.target_poison_assertion in doc_no_echo.text

def test_pure_topological_poison_attacker():
    from src.attacks.poisoning import PureTopologicalPoisonAttacker
    q = GoldQuery(
        id="Q-TOPO",
        query_text="What technique does APT28 use?",
        category="threat_actor_attribution",
        ground_truth_doc_ids=["DOC-APT28"],
        ground_truth_answer="APT28 uses PowerShell",
        target_poison_assertion="APT28 is harmless",
        key_terms=["APT28", "PowerShell"]
    )
    topo_attacker = PureTopologicalPoisonAttacker(bridge_count=10)
    p_doc = topo_attacker.generate_poison(q)

    assert p_doc.is_poisoned is True
    assert p_doc.poison_type == "pure_topological_poison"
    assert q.query_text not in p_doc.text
    for term in q.key_terms:
        assert term not in p_doc.text
        # Purity check: Target query terms must NOT be leaked into document entities
        assert term not in p_doc.entities
    assert len(p_doc.relations) == len(q.key_terms) * 10 * 2  # 2 terms * 10 bridges * 2 edges = 40

def test_evaluator_conditional_asr():
    queries = [
        GoldQuery("Q1", "Query 1", "cve", ["GT1"], "Ans", "Poison", ["Term1"]),
        GoldQuery("Q2", "Query 2", "cve", ["GT2"], "Ans", "Poison", ["Term2"]),
        GoldQuery("Q3", "Query 3", "cve", ["GT3"], "Ans", "Poison", ["Term3"]),
    ]

    # Suppose for Q1 and Q2, clean baseline found GT, but for Q3 clean baseline missed GT
    clean_hits = {"Q1": True, "Q2": True, "Q3": False}

    # In attack retrieval:
    # Q1: poisoned doc at top-1
    # Q2: clean doc at top-1
    # Q3: poisoned doc at top-1
    retrieval_outputs = {
        "Q1": [RetrievalResult("P1", 1.0, 1, "Poison 1", "Poison text", True, "poison")],
        "Q2": [RetrievalResult("GT2", 1.0, 1, "Clean 2", "Clean text", False, "cve")],
        "Q3": [RetrievalResult("P3", 1.0, 1, "Poison 3", "Poison text", True, "poison")],
    }

    res = Evaluator.evaluate_engine(
        engine_name="TestEngine",
        attack_type="sparse_b1",
        queries=queries,
        retrieval_outputs=retrieval_outputs,
        clean_ground_truth_hits=clean_hits
    )

    # Standard ASR@1: 2 poisoned top-1 out of 3 = 66.7%
    assert abs(res.retrieval_asr_top1 - 2.0 / 3.0) < 1e-4

    # Conditional ASR (ASR_cond): Conditioned on clean_hits (Q1, Q2):
    # Out of {Q1, Q2}, only Q1 has poison top-1 -> 1 out of 2 = 50.0%
    assert abs(res.retrieval_asr_cond - 0.5) < 1e-4

def test_poison_manager_with_blackbox_and_topological():
    clean_docs = build_cti_knowledge_base()
    queries = build_gold_benchmark_queries()
    poison_mgr = CorpusPoisonManager()

    for att in ["blackbox", "pure_topological"]:
        poisoned_corpus = poison_mgr.generate_poisoned_corpus(clean_docs, queries, att, attack_budget=2)
        assert len(poisoned_corpus) == len(clean_docs) + len(queries) * 2
        p_docs = [d for d in poisoned_corpus if d.is_poisoned]
        assert len(p_docs) == len(queries) * 2

def test_reporter_cross_matrix_includes_all_attacks_and_asr_cond_ci(tmp_path):
    from src.visualization.reporter import BenchmarkReporter
    from src.evaluation.metrics import EngineBenchmarkResult, GenerationTrace

    traces = [
        GenerationTrace("Q1", "cve", "Query 1", "Sparse-BM25", "pure_topological_b1", ["P1"], ["P1"], True, True, "", False, True, False, "", 1.0, 0.0, clean_ground_truth_hit=True),
        GenerationTrace("Q2", "cve", "Query 2", "Sparse-BM25", "pure_topological_b1", ["GT2"], ["GT2"], False, False, "", False, True, False, "", 1.0, 0.0, clean_ground_truth_hit=True),
    ]

    res_clean = EngineBenchmarkResult("Sparse-BM25", "clean_baseline", 2, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 1.0, 0.0, 0.0, traces=traces)
    res_topo = EngineBenchmarkResult("Sparse-BM25", "pure_topological_b1", 2, 0.5, 0.5, 0.5, 0.5, 0.5, 0.0, 0.5, 0.0, 0.5, traces=traces)

    rep_file = tmp_path / "test_report.md"
    md = BenchmarkReporter.generate_markdown_report([res_clean, res_topo], rep_file)

    # Pure topological must be in cross matrix
    assert "Pure Topological" in md
    # Conditional poison rate column must be present. Renamed from "ASR_cond": with no
    # generation stage this measures where the payload ranked, and ASR is reserved in the
    # literature for the share of answers the model actually adopted.
    assert "poison@1 cond (95% CI)" in md
    # Wilson CI on the conditional rate must be formatted
    assert "50.0% [" in md
    # Displacement must be reported alongside the payload's rank, never instead of it.
    assert "GT displaced@5" in md
