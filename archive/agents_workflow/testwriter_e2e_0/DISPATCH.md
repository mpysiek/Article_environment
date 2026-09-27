## 2026-09-06T20:01:02Z

You are the E2E Test Writer for the CTI RAG poisoning benchmark remediation project.
Your working directory is:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\testwriter_e2e_0
Your parent orchestrator is: dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635

MANDATORY FIRST STEP: Read the authoritative user requirements:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md

Read the project architecture and feature inventory:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\orchestrator_1\PROJECT.md

Your scope:
Design and implement a comprehensive opaque-box E2E test suite covering user requirements (R1 through R5) following the 4-tier methodology:
- Tier 1: Feature Coverage (>=5 test cases per feature across all inventoried features).
- Tier 2: Boundary & Corner Cases (>=5 test cases per feature where boundaries exist: empty inputs, missing fields, extreme budgets, 0% ASR, small McNemar counts, etc.).
- Tier 3: Cross-Feature Combinations (pairwise interactions: e.g., budget scaling with query_echo=False, GraphRAG with targeted vs untargeted ASR, LLM judge coverage with unparseable JSON and Pareto ranking).
- Tier 4: Real-World Application Scenarios (end-to-end evaluation runs on real CTI STIX / CVE queries, generating dynamic report outputs).

File Ownership:
- You exclusively own and write: `tests/test_e2e_remediation.py`
- You write project root indices: `TEST_INFRA.md` and `TEST_READY.md` (under d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\)
- You do NOT modify any source code files in `src/`.

Execution & Verification:
- Run tests using `.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py` (or verify that test structures are compilable and executable). Note that tests for features not yet implemented will serve as the acceptance criteria for ongoing implementation milestones.
- Write `TEST_INFRA.md` following the template in `PROJECT.md`.
- When complete, write `TEST_READY.md` summarizing total tests per tier and per feature.
- Write your handoff report to `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\testwriter_e2e_0\handoff.md`.
- Send completion message to parent (dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635).
