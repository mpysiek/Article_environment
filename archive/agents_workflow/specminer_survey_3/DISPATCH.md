## 2026-09-06T19:54:34Z
<USER_REQUEST>
You are a Specification Miner agent surveying LLM Judge evaluation and reporting rigor in the CTI RAG poisoning benchmark.
Your working directory is:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\specminer_survey_3
Your parent orchestrator is: dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635

MANDATORY FIRST STEP: Read the authoritative user requirements:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md

Your focus areas:
- R4: LLM Judge Robustness and Reliability (Class A8, A9, B8, B9 flaws)
- R5: Metrological Reporting Rigor, Pareto Analysis, and Statistical Correctness (Class A2, A10, B1, B2, B5, B10 flaws)
- Acceptance criteria: 100% passing tests, dynamic markdown report synthesis without hardcoded text/corpus size, Pareto ranking, exact McNemar test, p-value formatting.

Specific investigation tasks:
1. Examine LLM judge module: How are JSON parsing errors handled? How is `coverage_rate` tracked? Are assertions aligned with injected content for BlackBox and Topological attacks? How is `llm_stage_ran` flag handled when ASR=0? How does judge query deduplication operate?
2. Examine reporter and visualization (`src/visualization/reporter.py` and related): Where are hardcoded texts or static corpus sizes (e.g. 24,000 documents) located? How should report text be dynamically synthesized from results?
3. Examine ranking and statistical tests: How is Pareto ranking (Clean Recall@5 vs ASR) with utility threshold implemented or missing? Where are tie-breaking policies and cutoff $k$ values defined? How is latency measured (`time.perf_counter`, warm-up, median, IQR)? Where is the McNemar test implemented, and how must exact binomial test ($b+c < 25$) and p-value formatting ($p < 10^{-4}$) be structured?
4. Survey existing test suite (`tests/` directory): What tests currently exist, how are they run, what fixtures exist?
5. Enumerate all affected files and provide precise specifications and remediation requirements.

Deliverables:
- Update progress.md frequently.
- Write your specifications and findings to d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\specminer_survey_3\spec.md
- Write d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\specminer_survey_3\handoff.md
- Send a completion message to parent (dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635).
Do NOT write code to project source directories — you are read-only.
</USER_REQUEST>
