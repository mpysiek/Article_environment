# CTI RAG Poisoning Benchmark

Code and complete results for the article

> **Rank Placement Is Not Displacement: A Deterministic Benchmark of Retrieval-Layer Robustness
> to Corpus Poisoning in Cyber Threat Intelligence RAG**
> Mateusz Pyśk, Military University of Technology (WAT), 2026.

The benchmark isolates the **retrieval layer** of retrieval-augmented generation (RAG) for cyber
threat intelligence (CTI) and measures how corpus poisoning moves it. The generation stage is
intentionally not run, so every number is a deterministic, zero-cost measurement of retrieval.

| | |
| :--- | :--- |
| Corpus | 24,000 documents from MITRE ATT&CK (STIX 2.1), CTIBench, CISA KEV and CVE Program cvelistV5 |
| Queries | 150 in three strata: ATT&CK Relational, CVE Exact-Match, CVE Descriptive |
| Engines | Sparse-BM25, Dense-FAISS (bge-small-en-v1.5), Hybrid-Reranker (RRF + ms-marco-MiniLM-L-6-v2), GraphRAG (entity graph; called *Graph-Traversal* in the article) |
| Attacks | 9 vectors (incl. a `query_echo` stress arm and topological bridge injection), budgets 1, 2, 3, 5 |
| Protocol | per-query isolated index (`--isolated-targets`), no defences, top-k = 5, seed 42 |
| Metrics | `poison@1`, `poison@5`, `poison@1 cond`, `GT displaced@5`, with bounds over complete score-tie groups |

The article is the reference description of the study. Where this repository and the article
disagree, the article is right and the repository is to be corrected.

## Which run is which

| Folder | Role in the article |
| :--- | :--- |
| `outputs/reports/v3/` | **Main run.** Corrected question templates, full tie-group logging, bridge sweep, McNemar. |
| `outputs/reports/v2_rerun/` | Control re-run with the original templates, used for the template-sensitivity analysis. |
| `outputs/reports/v2/` | Archived first run (read-only, kept for comparison). |

Each folder holds the human-readable report (`rag_poisoning_comparison_report.md`), the run
manifest, and the full per-query results and traces (`*.json.xz`, compressed from ~130 MB).

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cpu
# exact versions of the reference run: requirements-lock.txt

pytest tests -q -p no:cacheprovider                     # 333 tests; test_data_integrity.py needs data/
```

### Check the published numbers without re-running anything

```bash
xz -dk outputs/reports/v3/*.json.xz
python scripts/audit_checks.py --in-dir outputs/reports/v3      # methodological gate K1–K9, TIE
python scripts/mcnemar_restricted.py --in-dir outputs/reports/v3
```

The audit gate on run v3 ends with `PASS: 9  FAIL: 0  INFO: 1`. GitHub Actions runs the tests
and this gate on every push.

`scripts/regenerate_report.py` rebuilds the report from stored traces and **overwrites** the
report in `--in-dir`. Scripts that write results refuse `outputs/reports/v2/`, the archived run.

### Re-run the benchmark

```bash
python scripts/run_v3_pipeline.py          # tests -> v2_rerun -> v3 -> sweep -> ties -> report -> McNemar
python scripts/run_v3_pipeline.py --from v3
```

The full pipeline runs on CPU and takes several hours. The first run downloads the source data
(~650 MB) and the two Hugging Face models. To get the same corpus as in the article, pin the
data versions as described in [`data/README.md`](data/README.md).

### Check that you have the article's corpus

The corpus text is not redistributed, but [`data/corpus_manifest_v2_24000.csv.xz`](data/README.md#which-corpus-the-article-used)
lists every document (ID, type, source, content hashes) in corpus order:

```bash
python scripts/corpus_manifest.py verify --corpus data/processed/real_cti_corpus_v2_24000.json
```

## Repository layout

```
src/
  corpus/         corpus assembly from authentic CTI sources, query sets v2 and v3
  engines/        the four retrievers
  attacks/        poisoning vectors and payload construction
  evaluation/     metrics, tie bounds, isolated and shared retrieval protocol
  visualization/  report generation and aggregation rules
scripts/          entry points: benchmark, bridge sweep, tie audit, audit gate, McNemar, pipeline, corpus manifest
tests/            333 tests (see tests/README.md)
outputs/          results of the runs reported in the article (see above) and their logs
data/             data provenance, checksums and the corpus manifest (the data itself is downloaded)
```

## Documentation

| File | Language | Contents |
| :--- | :--- | :--- |
| `README.md` | English | what the benchmark is, how to check and re-run it |
| [`data/README.md`](data/README.md) | English | data sources, versions, licences, checksums, corpus manifest |
| [`tests/README.md`](tests/README.md) | English | what each test file guards and how to run the suite |
| [`AGENTS.md`](AGENTS.md) | Polish | methodological rules the code enforces, state of each run, working rules for the repository |
| [`CHANGELOG.md`](CHANGELOG.md) | Polish | every change to the measurement and reporting layers |

Material removed from the repository stays in the git history; its last tracked state is
commit `bee8fe6`. That covers the agent workflow history, pre-1.3.0 code copies, superseded
scripts, the input sanitisers and the optional LLM generation and judging stage, which no
reported run used.

## Scope

* Only the retrieval layer is measured. The metrics are not attack success rates (ASR) in the
  generative sense.
* No defence is enabled; all figures are upper bounds for undefended retrieval.
* GraphRAG has no point estimate of `poison@1`: rank 1 is often a score tie, so results are
  reported as ranges over every ordering of the tie group.
* The engines are not ranked. Viable strata differ between engines, so per-engine averages
  describe different groups of queries.
* Hybrid-Reranker reranks a pool of 10 candidates fused by RRF from the top 10 of BM25 and of
  the dense engine. When the two lists share no document, each engine contributes only its
  ranks 1–5, so five payloads can push the answer out of the pool before the cross-encoder
  sees it.

## Names and counts in the article

| Article | Repository |
| :--- | :--- |
| Graph-Traversal | `GraphRAG` (the `engine_name` stored in the result files) |
| 429 tests | 333 tests. The article's code state is commit `1824048` (429 collected). Since then four corpus-manifest tests were added (433) and 100 tests were dropped with the LLM stage and the defence filters: 42 in four deleted files (batch client, judge, stages, defences) and 58 in other files (LLM judge, stage A/B/C serialisation, Pareto ranking). The tests of the retrieval measurement are unchanged |
| restricted McNemar family, 43 tests (Table 9) | `scripts/mcnemar_restricted.py`, files `mcnemar_restricted.*` |
| unrestricted family, 74 tests | Section 3.1 of `rag_poisoning_comparison_report.md` |

## Citation

See [`CITATION.cff`](CITATION.cff) or use **Cite this repository** on GitHub.

## Licence

Code and results: [MIT](LICENSE). Source data remains under the terms of its publishers
(see [`data/README.md`](data/README.md)).
